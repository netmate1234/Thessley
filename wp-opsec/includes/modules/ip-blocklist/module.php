<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-fetcher.php';
require_once __DIR__ . '/class-compiler.php';

class WPOpsec_Module_IP_Blocklist {

	const CRON_HOOK = 'wpopsec_ip_blocklist_refresh';

	public static function check_dest() {
		return WPOPSEC_CHECKS_DIR . '/ip-blocklist.php';
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
			unlink( self::check_dest() );
		}
	}

	public static function register() {
		self::deploy_check_file(); // keep in sync across plugin updates, same pattern as the mu-loader itself

		add_action( self::CRON_HOOK, array( __CLASS__, 'refresh' ) );
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_post_wpopsec_refresh_now', array( __CLASS__, 'handle_refresh_now' ) );
		add_action( 'admin_post_wpopsec_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wpopsec_add_local', array( __CLASS__, 'handle_add_local' ) );
		add_action( 'admin_post_wpopsec_remove_local', array( __CLASS__, 'handle_remove_local' ) );

		return __CLASS__;
	}

	public static function refresh() {
		$enabled = get_option( 'wpopsec_ip_blocklist_sources', WPOpsec_IP_Blocklist_Fetcher::DEFAULT_ENABLED );
		$ranges  = WPOpsec_IP_Blocklist_Fetcher::fetch_all( $enabled );
		$stats   = WPOpsec_IP_Blocklist_Compiler::compile( $ranges );

		$stats['updated_at'] = time();
		update_option( 'wpopsec_ip_blocklist_stats', $stats, false );

		// Piggyback the local blocklist's expiry sweep on this same cron run —
		// otherwise an escalated IP's compiled range file never gets rewritten
		// once it's past expires_at unless another IP happens to get added.
		wpopsec_local_blocklist_rebuild();

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
		}
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'IP Blocklist',
			'IP Blocklist',
			'manage_options',
			'wp-opsec-ip-blocklist',
			array( __CLASS__, 'render_settings_page' )
		);
	}

	public static function handle_refresh_now() {
		check_admin_referer( 'wpopsec_refresh_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		self::refresh();
		wp_safe_redirect( add_query_arg( 'refreshed', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$mode = ( isset( $_POST['mode'] ) && 'block' === $_POST['mode'] ) ? 'block' : 'log';
		update_option( 'wpopsec_ip_blocklist_mode', $mode );

		$allowlist_raw = isset( $_POST['allowlist'] ) ? wp_unslash( $_POST['allowlist'] ) : '';
		$allowlist     = array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $allowlist_raw ) ) );
		$allowlist     = array_values( array_filter( $allowlist, function ( $ip ) {
			return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
		} ) );
		update_option( 'wpopsec_ip_allowlist', $allowlist );

		$posted_sources = isset( $_POST['sources'] ) ? (array) wp_unslash( $_POST['sources'] ) : array();
		$sources        = array_values( array_intersect( $posted_sources, array_keys( WPOpsec_IP_Blocklist_Fetcher::SOURCES ) ) );
		update_option( 'wpopsec_ip_blocklist_sources', $sources );

		$trusted_file = isset( $_POST['trusted_networks_file'] ) ? trim( wp_unslash( $_POST['trusted_networks_file'] ) ) : '';
		update_option( 'wpopsec_trusted_networks_file', $trusted_file );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_add_local() {
		check_admin_referer( 'wpopsec_add_local' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$ip = isset( $_POST['ip'] ) ? trim( wp_unslash( $_POST['ip'] ) ) : '';
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : 'manual';
			$hours  = isset( $_POST['hours'] ) ? max( 1, (int) $_POST['hours'] ) : 24;
			wpopsec_local_blocklist_add( $ip, $reason ?: 'manual', $hours * HOUR_IN_SECONDS );
		}

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_remove_local() {
		check_admin_referer( 'wpopsec_remove_local' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$ip   = isset( $_POST['ip'] ) ? wp_unslash( $_POST['ip'] ) : '';
		$list = get_option( 'wpopsec_local_blocklist', array() );
		unset( $list[ $ip ] );
		update_option( 'wpopsec_local_blocklist', $list, false );
		wpopsec_local_blocklist_rebuild();

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$stats            = get_option( 'wpopsec_ip_blocklist_stats', array() );
		$mode             = get_option( 'wpopsec_ip_blocklist_mode', 'log' );
		$allowlist        = get_option( 'wpopsec_ip_allowlist', array() );
		$enabled_sources  = get_option( 'wpopsec_ip_blocklist_sources', WPOpsec_IP_Blocklist_Fetcher::DEFAULT_ENABLED );
		$trusted_file     = get_option( 'wpopsec_trusted_networks_file', '' );
		?>
		<div class="wrap">
			<h1>WP Opsec — IP Blocklist</h1>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['refreshed'] ) ) : ?>
				<div class="notice notice-success"><p>Blocklist refreshed.</p></div>
			<?php endif; ?>

			<h2>Status</h2>
			<?php if ( empty( $stats ) ) : ?>
				<p>No data yet.</p>
			<?php else : ?>
				<table class="widefat" style="max-width:500px">
					<tr><th>Last updated</th><td><?php echo esc_html( date( 'Y-m-d H:i:s', $stats['updated_at'] ) ); ?></td></tr>
					<tr><th>Ranges (merged)</th><td><?php echo esc_html( $stats['count_merged'] ); ?></td></tr>
					<?php foreach ( $stats['by_source'] as $src => $count ) : ?>
						<?php $label = WPOpsec_IP_Blocklist_Fetcher::SOURCES[ $src ]['label'] ?? ucfirst( $src ); ?>
						<tr><th><?php echo esc_html( $label ); ?> entries</th><td><?php echo esc_html( $count ); ?></td></tr>
					<?php endforeach; ?>
				</table>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wpopsec_refresh_now' ); ?>
				<input type="hidden" name="action" value="wpopsec_refresh_now">
				<?php submit_button( 'Refresh now', 'secondary', 'submit', false ); ?>
			</form>

			<h2>Local blocklist</h2>
			<p>IPs added here (manually, or auto-escalated by other modules like Query Guard) are checked alongside the reputation lists above, and expire automatically.</p>
			<?php $local = get_option( 'wpopsec_local_blocklist', array() ); ?>
			<?php if ( empty( $local ) ) : ?>
				<p>No local entries.</p>
			<?php else : ?>
				<table class="widefat" style="max-width:700px">
					<thead><tr><th>IP</th><th>Reason</th><th>Added</th><th>Expires</th><th></th></tr></thead>
					<tbody>
					<?php foreach ( $local as $ip => $entry ) : ?>
						<tr>
							<td><?php echo esc_html( $ip ); ?></td>
							<td><?php echo esc_html( $entry['reason'] ?? '' ); ?></td>
							<td><?php echo esc_html( date( 'Y-m-d H:i', $entry['added_at'] ?? 0 ) ); ?></td>
							<td><?php echo esc_html( date( 'Y-m-d H:i', $entry['expires_at'] ?? 0 ) ); ?></td>
							<td>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<?php wp_nonce_field( 'wpopsec_remove_local' ); ?>
									<input type="hidden" name="action" value="wpopsec_remove_local">
									<input type="hidden" name="ip" value="<?php echo esc_attr( $ip ); ?>">
									<?php submit_button( 'Remove', 'small', 'submit', false ); ?>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wpopsec_add_local' ); ?>
				<input type="hidden" name="action" value="wpopsec_add_local">
				<input type="text" name="ip" placeholder="1.2.3.4" required>
				<input type="text" name="reason" placeholder="reason (optional)">
				<input type="number" name="hours" value="24" min="1" style="width:5em"> hours
				<?php submit_button( 'Add to local blocklist', 'secondary', 'submit', false ); ?>
			</form>

			<h2>Settings</h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_save_settings">

				<table class="form-table">
					<tr>
						<th>Sources</th>
						<td>
							<?php foreach ( WPOpsec_IP_Blocklist_Fetcher::SOURCES as $id => $source ) : ?>
								<label>
									<input type="checkbox" name="sources[]" value="<?php echo esc_attr( $id ); ?>" <?php checked( in_array( $id, $enabled_sources, true ) ); ?>>
									<?php echo esc_html( $source['label'] ); ?>
								</label><br>
							<?php endforeach; ?>
							<p class="description">Changes take effect on the next refresh (cron or "Refresh now" below).</p>
						</td>
					</tr>
					<tr>
						<th>Mode</th>
						<td>
							<label><input type="radio" name="mode" value="log" <?php checked( $mode, 'log' ); ?>> Log only</label><br>
							<label><input type="radio" name="mode" value="block" <?php checked( $mode, 'block' ); ?>> Block (403)</label>
							<p class="description">Start in log-only mode, confirm no false positives, then switch to block.</p>
						</td>
					</tr>
					<tr>
						<th><label for="wpopsec_allowlist">Never-block IPs</label></th>
						<td>
							<textarea id="wpopsec_allowlist" name="allowlist" rows="4" cols="40"><?php echo esc_textarea( implode( "\n", $allowlist ) ); ?></textarea>
							<p class="description">One IPv4 per line. Always allowed regardless of blocklist match.</p>
						</td>
					</tr>
					<tr>
						<th><label for="wpopsec_trusted_file">Trusted networks file</label></th>
						<td>
							<input type="text" id="wpopsec_trusted_file" name="trusted_networks_file" value="<?php echo esc_attr( $trusted_file ); ?>" style="width:30em" placeholder="/etc/eagleeye/crawler-nets.conf">
							<?php if ( '' !== $trusted_file ) : ?>
								<?php $trusted_count = count( wpopsec_trusted_ranges() ); ?>
								<p class="description">
									<?php if ( is_readable( $trusted_file ) ) : ?>
										Readable — <?php echo esc_html( $trusted_count ); ?> network(s) loaded, e.g. known crawler ranges. Excluded from both the reputation-list compile and local escalation.
									<?php else : ?>
										<strong>Not readable</strong> by the web server user — check the path and permissions.
									<?php endif; ?>
								</p>
							<?php else : ?>
								<p class="description">Optional. Path to a CIDR-per-line file (e.g. known crawler/search-engine ranges) that's always exempt from blocking, on this and the local list.</p>
							<?php endif; ?>
						</td>
					</tr>
				</table>

				<?php submit_button( 'Save settings' ); ?>
			</form>
		</div>
		<?php
	}
}
