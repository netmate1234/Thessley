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

		return __CLASS__;
	}

	public static function refresh() {
		$enabled = get_option( 'wpopsec_ip_blocklist_sources', WPOpsec_IP_Blocklist_Fetcher::DEFAULT_ENABLED );
		$ranges  = WPOpsec_IP_Blocklist_Fetcher::fetch_all( $enabled );
		$stats   = WPOpsec_IP_Blocklist_Compiler::compile( $ranges );

		$stats['updated_at'] = time();
		update_option( 'wpopsec_ip_blocklist_stats', $stats, false );

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

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$stats            = get_option( 'wpopsec_ip_blocklist_stats', array() );
		$mode             = get_option( 'wpopsec_ip_blocklist_mode', 'log' );
		$allowlist        = get_option( 'wpopsec_ip_allowlist', array() );
		$enabled_sources  = get_option( 'wpopsec_ip_blocklist_sources', WPOpsec_IP_Blocklist_Fetcher::DEFAULT_ENABLED );
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
				</table>

				<?php submit_button( 'Save settings' ); ?>
			</form>
		</div>
		<?php
	}
}
