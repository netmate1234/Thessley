<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-fetcher.php';
require_once __DIR__ . '/class-compiler.php';

class ShieldCore_Module_IP_Blocklist {

	const CRON_HOOK = 'shieldcore_ip_blocklist_refresh';

	public static function check_dest() {
		return SHIELDCORE_CHECKS_DIR . '/ip-blocklist.php';
	}

	public static function activate() {
		self::deploy_check_file();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}

		// Populate the blocklist immediately so protection is live right away,
		// not just after tomorrow's cron run.
		self::refresh();
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );

		if ( file_exists( self::check_dest() ) ) {
			ShieldCore_Module_Loader::filesystem()->delete( self::check_dest() );
		}
	}

	public static function register() {
		self::deploy_check_file(); // keep in sync across plugin updates, same pattern as the mu-loader itself

		add_action( self::CRON_HOOK, array( __CLASS__, 'refresh' ) );
		add_action( 'admin_post_shieldcore_refresh_now', array( __CLASS__, 'handle_refresh_now' ) );
		add_action( 'admin_post_shieldcore_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_shieldcore_add_local', array( __CLASS__, 'handle_add_local' ) );
		add_action( 'admin_post_shieldcore_remove_local', array( __CLASS__, 'handle_remove_local' ) );

		return __CLASS__;
	}

	public static function refresh() {
		$enabled = get_option( 'shieldcore_ip_blocklist_sources', ShieldCore_IP_Blocklist_Fetcher::DEFAULT_ENABLED );
		$ranges  = ShieldCore_IP_Blocklist_Fetcher::fetch_all( $enabled );
		$stats   = ShieldCore_IP_Blocklist_Compiler::compile( $ranges );

		$stats['updated_at'] = time();
		update_option( 'shieldcore_ip_blocklist_stats', $stats, false );

		// Piggyback the local blocklist's expiry sweep on this same cron run —
		// otherwise an escalated IP's compiled range file never gets rewritten
		// once it's past expires_at unless another IP happens to get added.
		shieldcore_local_blocklist_rebuild();

		return $stats;
	}

	private static function deploy_check_file() {
		$dir = dirname( self::check_dest() );
		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$source = __DIR__ . '/check.php';
		if ( ! file_exists( self::check_dest() ) || md5_file( self::check_dest() ) !== md5_file( $source ) ) {
			copy( $source, self::check_dest() );
			// Without this, a worker process that already opcache-compiled the
			// old bytecode can keep serving stale check logic across multiple
			// requests until that cache entry's own revalidation timer fires —
			// a real, confirmed-live gap (hit an actual admin session's request
			// once via the mu-loader's own version of this same miss).
			if ( function_exists( 'opcache_invalidate' ) ) {
				opcache_invalidate( self::check_dest(), true );
			}
		}
	}


	public static function handle_refresh_now() {
		check_admin_referer( 'shieldcore_refresh_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		self::refresh();
		wp_safe_redirect( add_query_arg( 'refreshed', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'shieldcore_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$mode = ( isset( $_POST['mode'] ) && 'block' === $_POST['mode'] ) ? 'block' : 'log';
		update_option( 'shieldcore_ip_blocklist_mode', $mode );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- already unslashed, and array_intersect() against the real source-id list below discards anything not in it; nothing unvalidated ever reaches update_option().
		$posted_sources = isset( $_POST['sources'] ) ? (array) wp_unslash( $_POST['sources'] ) : array();
		$sources        = array_values( array_intersect( $posted_sources, array_keys( ShieldCore_IP_Blocklist_Fetcher::SOURCES ) ) );
		update_option( 'shieldcore_ip_blocklist_sources', $sources );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_add_local() {
		check_admin_referer( 'shieldcore_add_local' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated below via filter_var( ..., FILTER_VALIDATE_IP ) before it's ever used.
		$ip = isset( $_POST['ip'] ) ? trim( wp_unslash( $_POST['ip'] ) ) : '';
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : 'manual';
			$hours  = isset( $_POST['hours'] ) ? max( 1, (int) $_POST['hours'] ) : 24;
			shieldcore_local_blocklist_add( $ip, $reason ?: 'manual', $hours * HOUR_IN_SECONDS );
		}

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_remove_local() {
		check_admin_referer( 'shieldcore_remove_local' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only ever used as an array key for unset() below, never output or queried; this handler is already nonce-checked and manage_options-gated above.
		$ip   = isset( $_POST['ip'] ) ? wp_unslash( $_POST['ip'] ) : '';
		$list = get_option( 'shieldcore_local_blocklist', array() );
		unset( $list[ $ip ] );
		update_option( 'shieldcore_local_blocklist', $list, false );
		shieldcore_local_blocklist_rebuild();

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$stats           = get_option( 'shieldcore_ip_blocklist_stats', array() );
		$mode            = get_option( 'shieldcore_ip_blocklist_mode', 'log' );
		$enabled_sources = get_option( 'shieldcore_ip_blocklist_sources', ShieldCore_IP_Blocklist_Fetcher::DEFAULT_ENABLED );
		$local           = get_option( 'shieldcore_local_blocklist', array() );

		ShieldCore_UI::open( 'ip-blocklist' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			ShieldCore_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['refreshed'] ) ) {
			ShieldCore_UI::notice( 'success', 'Blocklist refreshed.' );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		ShieldCore_UI::tiles(
			array(
				array(
					'icon'  => 'block' === $mode ? 'shield-alt' : 'visibility',
					'tone'  => 'block' === $mode ? 'good' : 'warn',
					'value' => 'block' === $mode ? 'Blocking' : 'Log only',
					'label' => 'enforcement mode',
				),
				array(
					'icon'  => 'admin-site',
					'tone'  => 'quiet',
					'value' => number_format_i18n( (int) ( $stats['count_merged'] ?? 0 ) ),
					'label' => 'ranges loaded',
				),
				array(
					'icon'  => 'list-view',
					'tone'  => count( $local ) ? 'warn' : 'quiet',
					'value' => (string) count( $local ),
					'label' => 'local entries',
				),
				array(
					'icon'  => 'clock',
					'tone'  => 'quiet',
					'value' => ! empty( $stats['updated_at'] ) ? date_i18n( 'H:i', $stats['updated_at'] ) : '—',
					'label' => ! empty( $stats['updated_at'] ) ? 'updated ' . date_i18n( 'M j', $stats['updated_at'] ) : 'never updated',
				),
			)
		);

		ShieldCore_UI::section( 'Reputation feeds', 'admin-site' );
		if ( empty( $stats ) ) {
			echo '<div class="shieldcore-empty"><span class="dashicons dashicons-marker" style="color:#646970"></span><p>No data yet.</p></div>';
		} else {
			echo '<div class="shieldcore-table-scroll"><table class="shieldcore-table"><thead><tr><th>Source</th><th style="width:130px">Entries</th></tr></thead><tbody>';
			foreach ( $stats['by_source'] as $src => $count ) {
				$label = ShieldCore_IP_Blocklist_Fetcher::SOURCES[ $src ]['label'] ?? ucfirst( $src );
				printf(
					'<tr><td>%s</td><td>%s</td></tr>',
					esc_html( $label ),
					esc_html( number_format_i18n( $count ) )
				);
			}
			printf(
				'<tr><td><strong>Merged, after removing reserved and trusted ranges</strong></td><td><strong>%s</strong></td></tr>',
				esc_html( number_format_i18n( $stats['count_merged'] ) )
			);
			echo '</tbody></table></div>';
		}
		?>
		<div class="shieldcore-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'shieldcore_refresh_now' ); ?>
				<input type="hidden" name="action" value="shieldcore_refresh_now">
				<?php submit_button( 'Refresh now', 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
		ShieldCore_UI::section_end();

		uasort(
			$local,
			function ( $a, $b ) {
				return ( $b['added_at'] ?? 0 ) <=> ( $a['added_at'] ?? 0 );
			}
		);

		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only local-blocklist search/pagination, not a state-changing action; $lb_q is only used for a stripos() comparison and is esc_attr()'d wherever it's echoed back into the search box below, and $_GET['page']/['tab'] are only ever echoed into hidden fields via esc_attr(wp_unslash(...)).
		$lb_q = isset( $_GET['lb_q'] ) ? trim( wp_unslash( $_GET['lb_q'] ) ) : '';

		$local_filtered = $local;
		if ( '' !== $lb_q ) {
			$local_filtered = array_filter(
				$local,
				function ( $entry, $ip ) use ( $lb_q ) {
					return false !== stripos( $ip, $lb_q ) || false !== stripos( $entry['reason'] ?? '', $lb_q );
				},
				ARRAY_FILTER_USE_BOTH
			);
		}

		$lb_per_page = 25;
		$lb_total    = count( $local_filtered );
		$lb_pages    = max( 1, (int) ceil( $lb_total / $lb_per_page ) );
		$lb_page     = isset( $_GET['lb_page'] ) ? max( 1, (int) $_GET['lb_page'] ) : 1;
		$lb_page     = min( $lb_page, $lb_pages );
		$local_page  = array_slice( $local_filtered, ( $lb_page - 1 ) * $lb_per_page, $lb_per_page, true );

		ShieldCore_UI::section( 'Local blocklist', 'list-view', sprintf( '%d entry(s)', count( $local ) ) );
		echo '<p class="shieldcore-help" style="margin-top:0">IPs added here — manually, or auto-escalated by Query Guard and Login Guard — are checked alongside the feeds above, and expire automatically.</p>';
		?>
		<form method="get" style="margin:0 0 10px;display:flex;gap:6px;align-items:center">
			<input type="hidden" name="page" value="<?php echo esc_attr( wp_unslash( $_GET['page'] ?? '' ) ); ?>">
			<input type="hidden" name="tab" value="<?php echo esc_attr( wp_unslash( $_GET['tab'] ?? '' ) ); ?>">
			<input type="text" name="lb_q" value="<?php echo esc_attr( $lb_q ); ?>" placeholder="Search IP or reason&hellip;" style="width:220px">
			<?php submit_button( 'Search', 'secondary', 'submit', false ); ?>
			<?php if ( '' !== $lb_q ) : ?>
				<a href="<?php echo esc_url( remove_query_arg( array( 'lb_q', 'lb_page' ) ) ); ?>" class="button">Clear</a>
			<?php endif; ?>
		</form>
		<?php
		// phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( empty( $local_page ) ) {
			echo '<div class="shieldcore-empty"><span class="dashicons dashicons-yes-alt"></span><p>' . ( '' !== $lb_q ? 'No matches.' : 'No local entries.' ) . '</p></div>';
		} else {
			?>
			<div class="shieldcore-table-scroll">
			<table class="shieldcore-table">
				<thead><tr><th style="width:140px">IP</th><th>Reason</th><th style="width:130px">Added</th><th style="width:130px">Expires</th><th style="width:90px"></th></tr></thead>
				<tbody>
				<?php foreach ( $local_page as $ip => $entry ) : ?>
					<tr>
						<td class="shieldcore-nowrap"><code><?php echo esc_html( $ip ); ?></code></td>
						<td class="shieldcore-muted"><?php echo esc_html( $entry['reason'] ?? '' ); ?></td>
						<td class="shieldcore-nowrap shieldcore-muted"><?php echo esc_html( date_i18n( 'M j, H:i', $entry['added_at'] ?? 0 ) ); ?></td>
						<td class="shieldcore-nowrap shieldcore-muted"><?php echo esc_html( date_i18n( 'M j, H:i', $entry['expires_at'] ?? 0 ) ); ?></td>
						<td>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
								<?php wp_nonce_field( 'shieldcore_remove_local' ); ?>
								<input type="hidden" name="action" value="shieldcore_remove_local">
								<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>">
								<?php submit_button( 'Remove', 'small', 'submit', false ); ?>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			</div>
			<?php if ( $lb_pages > 1 ) : ?>
				<div class="shieldcore-actions" style="margin-top:10px;justify-content:flex-start;gap:10px;align-items:center">
					<?php if ( $lb_page > 1 ) : ?>
						<a class="button" href="<?php echo esc_url( add_query_arg( 'lb_page', $lb_page - 1 ) ); ?>">&laquo; Prev</a>
					<?php endif; ?>
					<span class="shieldcore-muted">Page <?php echo (int) $lb_page; ?> of <?php echo (int) $lb_pages; ?> (<?php echo (int) $lb_total; ?> entr<?php echo 1 === $lb_total ? 'y' : 'ies'; ?>)</span>
					<?php if ( $lb_page < $lb_pages ) : ?>
						<a class="button" href="<?php echo esc_url( add_query_arg( 'lb_page', $lb_page + 1 ) ); ?>">Next &raquo;</a>
					<?php endif; ?>
				</div>
			<?php endif; ?>
			<?php
		}
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:14px">
			<?php wp_nonce_field( 'shieldcore_add_local' ); ?>
			<input type="hidden" name="action" value="shieldcore_add_local">
			<div class="shieldcore-actions">
				<input type="text" name="ip" placeholder="1.2.3.4" required>
				<input type="text" name="reason" placeholder="reason (optional)">
				<input type="number" name="hours" value="24" min="1" style="width:5em"> hours
				<?php submit_button( 'Add', 'secondary', 'submit', false ); ?>
			</div>
		</form>
		<?php
		ShieldCore_UI::section_end();
		?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'shieldcore_save_settings' ); ?>
			<input type="hidden" name="action" value="shieldcore_save_settings">

			<?php ShieldCore_UI::section( 'Settings', 'admin-generic' ); ?>
				<?php
				ShieldCore_UI::row(
					'Sources',
					function () use ( $enabled_sources ) {
						foreach ( ShieldCore_IP_Blocklist_Fetcher::SOURCES as $id => $source ) {
							?>
							<label>
								<input type="checkbox" name="sources[]" value="<?php echo esc_attr( $id ); ?>" <?php checked( in_array( $id, $enabled_sources, true ) ); ?>>
								<?php echo esc_html( $source['label'] ); ?>
							</label>
							<?php
						}
					},
					'Changes take effect on the next refresh. Private and reserved IP space is always excluded, whatever a feed says — a bogon source address only ever means a LAN client or a proxy hop. The unwantedip source needs an API key from the <a href="' . esc_url( ShieldCore_Menu_Router::url( 'ip-sharing' ) ) . '">IP Sharing tab</a> first — it\'s silently skipped, not treated as a failed fetch, until one is set.'
				);

				ShieldCore_UI::row(
					'Mode',
					function () use ( $mode ) {
						?>
						<label><input type="radio" name="mode" value="log" <?php checked( $mode, 'log' ); ?>> Log only</label>
						<label><input type="radio" name="mode" value="block" <?php checked( $mode, 'block' ); ?>> Block (403)</label>
						<?php
					},
					'Start in log-only mode, confirm no false positives in the Event Log, then switch to block.'
				);

				ShieldCore_UI::row(
					'Whitelist',
					function () {
						?>
						<a href="<?php echo esc_url( ShieldCore_Menu_Router::url( 'whitelist' ) ); ?>">Manage on the Whitelist tab →</a>
						<?php
					},
					'Individually-listed IPs and the trusted-networks CIDR file both moved there since they apply to every blocking module, not just this one — geo-blocking, rate limiting, login guard, and the rest all honor them too.'
				);
				?>
			<?php ShieldCore_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		ShieldCore_UI::close();
	}
}
