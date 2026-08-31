<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-country-codes.php';

/**
 * Country-level blocking.
 *
 * IP-to-country data comes from DB-IP's free "Country Lite" database
 * (CC BY 4.0, no registration required) — roughly 358,000 IPv4 ranges,
 * updated monthly. That's ~19x larger than any other list this plugin
 * compiles, and a plain PHP-array-plus-binary-search (the pattern used for
 * ip-blocklist) would mean a multi-megabyte array baked into opcache on
 * every server running this plugin. Instead the compiled data is a flat
 * binary file of fixed 9-byte records (4-byte start, 4-byte end, 1-byte
 * country index), sorted by start, and the early-gate check does a
 * classic on-disk binary search via fseek/fread — no PHP array, no
 * meaningful per-request memory cost, ~19 seeks per lookup.
 *
 * The check itself never needs country *names* — the admin's blocked/
 * allowed selection is converted to a small set of integer indices at
 * save time, and the hot path only ever compares integers.
 */
class WPOpsec_Module_Geo_Blocker {

	const CRON_HOOK    = 'wpopsec_geo_refresh';
	const RECORD_SIZE  = 9; // 4 + 4 + 1 bytes
	const SOURCE_BASE  = 'https://download.db-ip.com/free/dbip-country-lite-';

	public static function data_file() {
		return WPOPSEC_CHECKS_DIR . '/data/geo-country-index.bin';
	}

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 50 * MINUTE_IN_SECONDS ), 'weekly', self::CRON_HOOK );
		}
		self::deploy_check_file();
		self::refresh();
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		if ( file_exists( self::check_dest() ) ) {
			unlink( self::check_dest() );
		}
	}

	public static function check_dest() {
		return WPOPSEC_CHECKS_DIR . '/geo-blocker.php';
	}

	private static function deploy_check_file() {
		$dir = dirname( self::check_dest() );
		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$source = __DIR__ . '/check.php';
		if ( ! file_exists( self::check_dest() ) || md5_file( self::check_dest() ) !== md5_file( $source ) ) {
			copy( $source, self::check_dest() );
		}
	}

	public static function register() {
		self::deploy_check_file();

		add_action( self::CRON_HOOK, array( __CLASS__, 'refresh' ) );
		add_action( 'admin_post_wpopsec_geo_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wpopsec_geo_refresh_now', array( __CLASS__, 'handle_refresh_now' ) );

		return __CLASS__;
	}

	/** DB-IP publishes monthly; try the current month, fall back a month if not out yet. */
	private static function download_csv() {
		foreach ( array( 0, 1, 2 ) as $months_back ) {
			$ts  = strtotime( "-{$months_back} months" );
			$url = self::SOURCE_BASE . date( 'Y-m', $ts ) . '.csv.gz';

			$response = wp_remote_get( $url, array( 'timeout' => 60 ) );
			if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
				continue;
			}

			$gz = @gzdecode( wp_remote_retrieve_body( $response ) );
			if ( false !== $gz && strlen( $gz ) > 1000 ) {
				return $gz;
			}
		}
		return false;
	}

	public static function refresh() {
		$csv = self::download_csv();
		if ( false === $csv ) {
			wpopsec_log_event( 'geo-blocker', 'refresh_failed', 'noted', 'could not download the DB-IP country dataset', 6 );
			return false;
		}

		$indices = WPOpsec_Geo_Country_Codes::indices();
		$ranges  = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $csv ) as $line ) {
			if ( '' === $line || false !== strpos( $line, ':' ) ) {
				continue; // blank line, or IPv6 (always contains a colon) — IPv4-only, matching the rest of the plugin
			}
			$fields = explode( ',', $line );
			if ( count( $fields ) < 3 ) {
				continue;
			}
			$start = ip2long( $fields[0] );
			$end   = ip2long( $fields[1] );
			$idx   = $indices[ trim( $fields[2] ) ] ?? null;
			if ( false === $start || false === $end || null === $idx ) {
				continue;
			}
			$ranges[] = array( $start, $end, $idx );
		}

		if ( count( $ranges ) < 1000 ) {
			// Sanity floor: a parse gone wrong (format change upstream)
			// should never silently replace a good index with an empty one.
			wpopsec_log_event( 'geo-blocker', 'refresh_suspicious', 'noted', sprintf( 'only %d ranges parsed, keeping previous index', count( $ranges ) ), 8 );
			return false;
		}

		// DB-IP ships pre-sorted, but this runs once a month — the cost of
		// verifying that invariant instead of trusting it blindly is trivial.
		usort( $ranges, function ( $a, $b ) { return $a[0] <=> $b[0]; } );

		self::write_index( $ranges );
		self::write_names_map();

		update_option( 'wpopsec_geo_stats', array( 'count' => count( $ranges ), 'updated_at' => time() ), false );
		wpopsec_log_event( 'geo-blocker', 'refreshed', 'noted', sprintf( '%d ranges compiled', count( $ranges ) ), 2 );

		return count( $ranges );
	}

	private static function write_index( array $ranges ) {
		$file = self::data_file();
		$dir  = dirname( $file );
		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$tmp = $file . '.tmp-' . bin2hex( random_bytes( 4 ) );
		$fh  = fopen( $tmp, 'wb' );
		foreach ( $ranges as $r ) {
			fwrite( $fh, pack( 'NNC', $r[0], $r[1], $r[2] ) );
		}
		fclose( $fh );
		rename( $tmp, $file );

		// Not opcache-relevant (this isn't PHP source), but the file is
		// reopened per request via fopen/fseek, so no cache to invalidate —
		// noted here only so the parallel with the other compiled sources is explicit.
	}

	/**
	 * A tiny index-to-"Name (CODE)" map, written alongside the binary
	 * index so check.php — which runs pre-bootstrap and can't load this
	 * plugin's classes — can turn a match into a readable log line without
	 * carrying the full ~250-entry country list into the early gate.
	 */
	private static function write_names_map() {
		$codes = array_keys( WPOpsec_Geo_Country_Codes::all() );
		$names = array_values( WPOpsec_Geo_Country_Codes::all() );

		$labels = array();
		foreach ( $names as $i => $name ) {
			$labels[ $i ] = "{$name} ({$codes[ $i ]})";
		}

		$file   = dirname( self::data_file() ) . '/geo-country-names.php';
		$export = "<?php\n// Auto-generated by wp-opsec geo-blocker module. Do not edit.\nreturn " . var_export( $labels, true ) . ";\n";

		$tmp = $file . '.tmp-' . bin2hex( random_bytes( 4 ) );
		file_put_contents( $tmp, $export, LOCK_EX );
		rename( $tmp, $file );

		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $file, true );
		}
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_geo_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$mode = ( isset( $_POST['mode'] ) && 'allowlist' === $_POST['mode'] ) ? 'allowlist' : 'blocklist';
		update_option( 'wpopsec_geo_mode', $mode );

		update_option( 'wpopsec_geo_enforce_mode', ( isset( $_POST['enforce'] ) && 'block' === $_POST['enforce'] ) ? 'block' : 'log' );

		$posted = isset( $_POST['countries'] ) ? (array) wp_unslash( $_POST['countries'] ) : array();
		$codes  = array_values( array_intersect( $posted, array_keys( WPOpsec_Geo_Country_Codes::all() ) ) );
		update_option( 'wpopsec_geo_countries', $codes );

		// Pre-compute the index set the hot path actually reads, so the
		// early gate never has to load the country-name list at all.
		$indices = array();
		foreach ( $codes as $code ) {
			$i = WPOpsec_Geo_Country_Codes::index_of( $code );
			if ( null !== $i ) {
				$indices[] = $i;
			}
		}
		update_option( 'wpopsec_geo_country_indices', $indices, false );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_refresh_now() {
		check_admin_referer( 'wpopsec_geo_refresh_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::refresh();
		wp_safe_redirect( add_query_arg( 'refreshed', '1', wp_get_referer() ) );
		exit;
	}


	public static function render_page() {
		$stats     = get_option( 'wpopsec_geo_stats', array() );
		$mode      = get_option( 'wpopsec_geo_mode', 'blocklist' );
		$enforce   = get_option( 'wpopsec_geo_enforce_mode', 'log' );
		$selected  = (array) get_option( 'wpopsec_geo_countries', array() );

		WPOpsec_UI::open( 'geo-blocker' );

		if ( isset( $_GET['saved'] ) ) {
			WPOpsec_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['refreshed'] ) ) {
			WPOpsec_UI::notice( 'success', 'Country index refreshed.' );
		}

		WPOpsec_UI::tiles(
			array(
				array(
					'icon'  => 'block' === $enforce ? 'shield-alt' : 'visibility',
					'tone'  => 'block' === $enforce ? 'good' : 'warn',
					'value' => 'block' === $enforce ? 'Blocking' : 'Log only',
					'label' => 'enforcement mode',
				),
				array(
					'icon'  => 'admin-site-alt3',
					'tone'  => 'quiet',
					'value' => 'allowlist' === $mode ? 'Allow-list' : 'Block-list',
					'label' => 'allowlist' === $mode ? 'only listed countries' : 'listed countries blocked',
				),
				array(
					'icon'  => 'admin-site',
					'tone'  => 'quiet',
					'value' => ! empty( $stats['count'] ) ? number_format_i18n( $stats['count'] ) : '—',
					'label' => ! empty( $stats['updated_at'] ) ? 'ranges, updated ' . date_i18n( 'M j', $stats['updated_at'] ) : 'not fetched yet',
				),
			)
		);

		?>
		<div class="wpopsec-actions" style="margin-bottom:18px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_geo_refresh_now' ); ?>
				<input type="hidden" name="action" value="wpopsec_geo_refresh_now">
				<?php submit_button( 'Refresh country index now', 'secondary', 'submit', false ); ?>
			</form>
		</div>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wpopsec_geo_save_settings' ); ?>
			<input type="hidden" name="action" value="wpopsec_geo_save_settings">

			<?php WPOpsec_UI::section( 'Mode', 'admin-site-alt3' ); ?>
				<?php
				WPOpsec_UI::row(
					'List type',
					function () use ( $mode ) {
						?>
						<label><input type="radio" name="mode" value="blocklist" <?php checked( $mode, 'blocklist' ); ?>> Block-list — deny the countries checked below, allow everyone else</label>
						<label><input type="radio" name="mode" value="allowlist" <?php checked( $mode, 'allowlist' ); ?>> Allow-list — allow only the countries checked below, deny everyone else</label>
						<?php
					},
					'Allow-list is a hard lockdown, appropriate for a site with a genuinely regional audience. IP-to-country data is inherently approximate — VPNs, satellite links and mobile carriers routinely appear to originate from the wrong country — so treat this as a coarse filter, not a guarantee.'
				);

				WPOpsec_UI::row(
					'Enforcement',
					function () use ( $enforce ) {
						?>
						<label><input type="radio" name="enforce" value="log" <?php checked( $enforce, 'log' ); ?>> Log only</label>
						<label><input type="radio" name="enforce" value="block" <?php checked( $enforce, 'block' ); ?>> Block (403)</label>
						<?php
					},
					'As with every other blocking module: your LAN, reserved IP space, and anything in the trusted-networks file are permanently exempt, regardless of what country they resolve to.'
				);
				?>
			<?php WPOpsec_UI::section_end(); ?>

			<?php WPOpsec_UI::section( 'Countries', 'admin-site' ); ?>
				<div class="wpopsec-scroll" style="max-height:320px">
					<?php foreach ( WPOpsec_Geo_Country_Codes::all() as $code => $name ) : ?>
						<?php if ( 'ZZ' === $code ) { continue; } /* reserved space, not a real country to pick */ ?>
						<label style="display:inline-block;width:47%">
							<input type="checkbox" name="countries[]" value="<?php echo esc_attr( $code ); ?>" <?php checked( in_array( $code, $selected, true ) ); ?>>
							<?php echo esc_html( $name ); ?> <span class="wpopsec-muted">(<?php echo esc_html( $code ); ?>)</span>
						</label>
					<?php endforeach; ?>
				</div>
				<p class="wpopsec-help">IP geolocation data: <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP.com</a> Country Lite, used under CC BY 4.0, refreshed weekly.</p>
			<?php WPOpsec_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		WPOpsec_UI::close();
	}
}
