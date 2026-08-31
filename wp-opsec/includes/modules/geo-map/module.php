<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only visualization, not a gate: no check.php, nothing runs on the
 * request path. Aggregates the shared events table by country and tints
 * an embedded world map accordingly.
 *
 * Country resolution reuses geo-blocker's compiled binary index and
 * names map (wpopsec_geo_lookup() / wpopsec_geo_country_label(), both
 * defined by geo-blocker's check.php once that module has been active at
 * least once) rather than adding a third geo dataset. If geo-blocker has
 * never run, this page just has nothing to color — it degrades to an
 * empty map, not an error.
 */
class WPOpsec_Module_Geo_Map {

	/** 5-step intensity scale, light to dark, independent of the severity palette. */
	const BUCKET_COLORS = array( '#c7e3ff', '#7fb8f2', '#3d84d6', '#b26e00', '#8b0a3e' );

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		return __CLASS__;
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'Event Map',
			'Event Map',
			'manage_options',
			'wp-opsec-geo-map',
			array( __CLASS__, 'render_page' )
		);
	}

	/**
	 * @return array<string,int> ISO 3166-1 alpha-2 code (uppercase) => event count
	 */
	public static function counts_by_country( $days ) {
		global $wpdb;

		$table = wpopsec_events_table();

		// Aggregate by IP first — far fewer unique IPs than raw events, so
		// country resolution (a binary search per IP) stays cheap even on a
		// busy site. The 2000-IP cap is a safety valve, not a real-world
		// ceiling: that many distinct attacking IPs in one window is already
		// an extreme outlier worth its own investigation, not a map.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip, COUNT(*) c FROM {$table}
				 WHERE action IN ('blocked','logged') AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
				 GROUP BY ip ORDER BY c DESC LIMIT 2000",
				$days
			),
			ARRAY_A
		) ?: array();

		$by_country = array();
		$geo_ready  = function_exists( 'wpopsec_geo_lookup' ) && function_exists( 'wpopsec_geo_country_label' );
		$file       = WPMU_PLUGIN_DIR . '/wp-opsec-checks/data/geo-country-index.bin';

		foreach ( $rows as $row ) {
			if ( ! $geo_ready || wpopsec_ip_is_reserved( $row['ip'] ) ) {
				continue;
			}
			$long = ip2long( $row['ip'] );
			if ( false === $long ) {
				continue;
			}
			$idx = wpopsec_geo_lookup( $file, $long );
			if ( null === $idx ) {
				continue;
			}
			$label = wpopsec_geo_country_label( $idx );
			if ( ! preg_match( '/\(([A-Z]{2})\)$/', $label, $m ) ) {
				continue; // "index N" fallback — dataset missing, nothing to plot
			}
			$code                = $m[1];
			$by_country[ $code ] = ( $by_country[ $code ] ?? 0 ) + (int) $row['c'];
		}

		return $by_country;
	}

	/** Injects a class + data attributes into every <path id="xx" .../> that has data. */
	private static function tint_svg( $svg, array $by_country ) {
		if ( empty( $by_country ) ) {
			return $svg;
		}

		$max     = max( $by_country );
		$log_max = log( $max + 1 );
		$codes   = WPOpsec_Geo_Country_Codes::all();

		foreach ( $by_country as $code => $count ) {
			$name   = $codes[ $code ] ?? $code;
			$bucket = $log_max > 0 ? min( 4, (int) floor( ( log( $count + 1 ) / $log_max ) * 5 ) ) : 0;
			$id     = strtolower( $code );

			$replacement = sprintf(
				'id="%s" class="wpopsec-geo-hit wpopsec-geo-b%d" data-country="%s" data-count="%d"',
				$id,
				$bucket,
				esc_attr( $name ),
				$count
			);
			$svg = preg_replace_callback(
				'/id="' . preg_quote( $id, '/' ) . '"/',
				function () use ( $replacement ) {
					return $replacement;
				},
				$svg
			);
		}

		return $svg;
	}

	public static function render_page() {
		$days       = isset( $_GET['days'] ) ? max( 1, (int) $_GET['days'] ) : 7;
		$by_country = self::counts_by_country( $days );
		$svg_path   = __DIR__ . '/assets/world-map.svg';
		$svg        = is_readable( $svg_path ) ? file_get_contents( $svg_path ) : '';
		$svg        = self::tint_svg( $svg, $by_country );

		arsort( $by_country );
		$codes = WPOpsec_Geo_Country_Codes::all();

		WPOpsec_UI::open( 'geo-map' );

		WPOpsec_UI::tiles(
			array(
				array( 'icon' => 'admin-site-alt3', 'tone' => 'quiet', 'value' => number_format_i18n( count( $by_country ) ), 'label' => 'countries seen' ),
				array( 'icon' => 'clock', 'tone' => 'quiet', 'value' => sprintf( 'last %d day(s)', $days ), 'label' => 'window' ),
			)
		);

		?>
		<form method="get" style="margin-bottom:14px">
			<input type="hidden" name="page" value="wp-opsec-geo-map">
			<label>Window:
				<select name="days" onchange="this.form.submit()">
					<?php foreach ( array( 1 => '24 hours', 7 => '7 days', 30 => '30 days', 90 => '90 days' ) as $val => $label ) : ?>
						<option value="<?php echo esc_attr( $val ); ?>" <?php selected( $days, $val ); ?>><?php echo esc_html( $label ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
		</form>

		<?php WPOpsec_UI::section( 'Activity by country', 'admin-site-alt3' ); ?>
			<?php if ( empty( $by_country ) ) : ?>
				<div class="wpopsec-empty"><span class="dashicons dashicons-info-outline"></span><p>No blocked or logged events with a resolvable country in this window.</p></div>
			<?php else : ?>
				<div class="wpopsec-geo-map-wrap"><?php echo $svg; /* server-generated, country codes and counts only */ ?></div>
				<div id="wpopsec-geo-tip" class="wpopsec-geo-tip"></div>
			<?php endif; ?>
		<?php WPOpsec_UI::section_end(); ?>

		<?php if ( ! empty( $by_country ) ) : ?>
			<?php WPOpsec_UI::section( 'Top countries', 'list-view' ); ?>
				<table class="wpopsec-table">
					<thead><tr><th>Country</th><th style="width:120px">Events</th><th>Share</th></tr></thead>
					<tbody>
					<?php $top = array_slice( $by_country, 0, 15, true ); ?>
					<?php $max = max( $by_country ); ?>
					<?php foreach ( $top as $code => $count ) : ?>
						<tr>
							<td><?php echo esc_html( ( $codes[ $code ] ?? $code ) . " ({$code})" ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $count ) ); ?></td>
							<td style="width:200px">
								<div style="background:#f0f0f1;border-radius:3px;overflow:hidden;height:8px">
									<div style="background:#3d84d6;height:8px;width:<?php echo esc_attr( max( 4, (int) round( ( $count / $max ) * 100 ) ) ); ?>%"></div>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php WPOpsec_UI::section_end(); ?>
		<?php endif; ?>

		<p class="wpopsec-help">Country resolution reuses the Geo Blocker module's dataset (DB-IP Country Lite, CC BY 4.0) — enable that module at least once for this map to have data. Map graphic: <a href="https://github.com/flekschas/simple-world-map" target="_blank" rel="noopener">flekschas/simple-world-map</a>, CC BY-SA 3.0.</p>

		<style>
		.wpopsec-geo-map-wrap { max-width:100%; overflow-x:auto; }
		.wpopsec-geo-map-wrap svg { width:100%; height:auto; max-height:520px; }
		.wpopsec-geo-map-wrap svg path { fill:#e2e4e8; stroke:#fff; stroke-width:0.4; }
		<?php foreach ( self::BUCKET_COLORS as $i => $color ) : ?>
		.wpopsec-geo-map-wrap svg path.wpopsec-geo-b<?php echo (int) $i; ?> { fill:<?php echo esc_html( $color ); ?>; cursor:pointer; }
		<?php endforeach; ?>
		.wpopsec-geo-map-wrap svg path.wpopsec-geo-hit:hover { stroke:#1d2327; stroke-width:1.2; }
		.wpopsec-geo-tip { position:fixed; display:none; pointer-events:none; z-index:9999;
			background:#1d2327; color:#fff; font-size:12px; padding:5px 9px; border-radius:5px;
			box-shadow:0 2px 8px rgba(0,0,0,.25); white-space:nowrap; }
		</style>
		<script>
		(function () {
			var wrap = document.querySelector( '.wpopsec-geo-map-wrap' );
			var tip  = document.getElementById( 'wpopsec-geo-tip' );
			if ( ! wrap || ! tip ) { return; }
			wrap.addEventListener( 'mousemove', function ( e ) {
				var el = e.target.closest ? e.target.closest( '.wpopsec-geo-hit' ) : null;
				if ( ! el ) { tip.style.display = 'none'; return; }
				tip.textContent = el.getAttribute( 'data-country' ) + ': ' + el.getAttribute( 'data-count' ) + ' event(s)';
				tip.style.left = ( e.clientX + 14 ) + 'px';
				tip.style.top  = ( e.clientY + 14 ) + 'px';
				tip.style.display = 'block';
			} );
			wrap.addEventListener( 'mouseleave', function () { tip.style.display = 'none'; } );
		})();
		</script>
		<?php
		WPOpsec_UI::close();
	}
}
