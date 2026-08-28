<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WPOpsec_Module_Query_Guard {

	const CATEGORIES = array(
		'sqli'      => 'SQL injection',
		'xss'       => 'Cross-site scripting',
		'traversal' => 'Path traversal / file inclusion',
		'cmdi'      => 'Command injection / webshell probes',
		'other'     => 'Misc (null bytes, etc.)',
	);

	const JETPACK_IP_SOURCE = 'https://jetpack.com/ips-v4.txt';
	const XMLRPC_CRON_HOOK  = 'wpopsec_qg_xmlrpc_allow_refresh';

	public static function check_dest() {
		return WPOPSEC_CHECKS_DIR . '/query-guard.php';
	}

	public static function activate() {
		self::deploy_check_file();

		if ( ! wp_next_scheduled( self::XMLRPC_CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::XMLRPC_CRON_HOOK );
		}
		self::refresh_xmlrpc_allowlist();
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::XMLRPC_CRON_HOOK );

		if ( file_exists( self::check_dest() ) ) {
			unlink( self::check_dest() );
		}
	}

	public static function register() {
		self::deploy_check_file();

		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_post_wpopsec_qg_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wpopsec_qg_refresh_xmlrpc_allow', array( __CLASS__, 'handle_refresh_xmlrpc_allow' ) );
		add_action( self::XMLRPC_CRON_HOOK, array( __CLASS__, 'refresh_xmlrpc_allowlist' ) );

		return __CLASS__;
	}

	/**
	 * Jetpack is the one common legitimate xmlrpc.php consumer, and
	 * Automattic publishes a live, auto-updating IP list for exactly this
	 * purpose rather than a static one that goes stale — fetch and cache
	 * it, same daily-refresh pattern as ip-blocklist's sources. Anything
	 * else (other providers) goes through the existing trusted-networks
	 * file instead of us guessing at more hardcoded IP data.
	 */
	public static function refresh_xmlrpc_allowlist() {
		$response = wp_remote_get( self::JETPACK_IP_SOURCE, array( 'timeout' => 15, 'user-agent' => 'wp-opsec/' . WPOPSEC_VERSION ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$ranges = array();
		foreach ( preg_split( '/\r\n|\r|\n/', wp_remote_retrieve_body( $response ) ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || false === strpos( $line, '/' ) ) {
				continue;
			}
			$ranges[] = wpopsec_cidr_to_range( $line );
		}

		update_option( 'wpopsec_qg_xmlrpc_allow_ranges', $ranges, false );
		update_option( 'wpopsec_qg_xmlrpc_allow_updated_at', time(), false );

		return count( $ranges );
	}

	public static function handle_refresh_xmlrpc_allow() {
		check_admin_referer( 'wpopsec_qg_refresh_xmlrpc_allow' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		self::refresh_xmlrpc_allowlist();
		wp_safe_redirect( add_query_arg( 'refreshed', '1', wp_get_referer() ) );
		exit;
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
			'Query Guard',
			'Query Guard',
			'manage_options',
			'wp-opsec-query-guard',
			array( __CLASS__, 'render_settings_page' )
		);
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_qg_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$mode = ( isset( $_POST['mode'] ) && 'block' === $_POST['mode'] ) ? 'block' : 'log';
		update_option( 'wpopsec_query_guard_mode', $mode );

		$posted     = isset( $_POST['categories'] ) ? (array) wp_unslash( $_POST['categories'] ) : array();
		$categories = array_values( array_intersect( $posted, array_keys( self::CATEGORIES ) ) );
		update_option( 'wpopsec_query_guard_categories', $categories );

		update_option( 'wpopsec_query_guard_block_xmlrpc', isset( $_POST['block_xmlrpc'] ) );
		update_option( 'wpopsec_qg_allow_jetpack', isset( $_POST['allow_jetpack'] ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$mode          = get_option( 'wpopsec_query_guard_mode', 'log' );
		$categories    = get_option( 'wpopsec_query_guard_categories', array_keys( self::CATEGORIES ) );
		$block_xmlrpc  = get_option( 'wpopsec_query_guard_block_xmlrpc', false );
		$allow_jetpack = get_option( 'wpopsec_qg_allow_jetpack', true );
		$jp_ranges     = get_option( 'wpopsec_qg_xmlrpc_allow_ranges', array() );
		$jp_updated_at = get_option( 'wpopsec_qg_xmlrpc_allow_updated_at', 0 );
		?>
		<div class="wrap">
			<h1>WP Opsec — Query Guard</h1>
			<p>Scans the GET query string of every request for common attack signatures (SQLi, XSS, path traversal, command injection). POST bodies are never inspected, to avoid false positives against legitimate content like the block editor.</p>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['refreshed'] ) ) : ?>
				<div class="notice notice-success"><p>Jetpack IP list refreshed.</p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_qg_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_qg_save_settings">

				<table class="form-table">
					<tr>
						<th>Categories</th>
						<td>
							<?php foreach ( self::CATEGORIES as $id => $label ) : ?>
								<label>
									<input type="checkbox" name="categories[]" value="<?php echo esc_attr( $id ); ?>" <?php checked( in_array( $id, $categories, true ) ); ?>>
									<?php echo esc_html( $label ); ?>
								</label><br>
							<?php endforeach; ?>
						</td>
					</tr>
					<tr>
						<th>xmlrpc.php</th>
						<td>
							<label><input type="checkbox" name="block_xmlrpc" <?php checked( $block_xmlrpc ); ?>> Block access to xmlrpc.php entirely</label>
							<p class="description">Off by default — xmlrpc.php is needed by Jetpack and some remote-publishing tools. Enable only if you know this site doesn't use it. Any access while enabled is treated as an attack: pingback-based DDoS amplification and password-guessing via its multicall method are the common abuses.</p>

							<label style="display:block;margin-top:.5em"><input type="checkbox" name="allow_jetpack" <?php checked( $allow_jetpack ); ?>> Still allow Jetpack (Automattic) IPs through</label>
							<p class="description">
								Fetched from Automattic's own published list, refreshed daily.
								<?php if ( $jp_updated_at ) : ?>
									Currently <?php echo esc_html( count( $jp_ranges ) ); ?> range(s), last updated <?php echo esc_html( date( 'Y-m-d H:i', $jp_updated_at ) ); ?>.
								<?php else : ?>
									Not fetched yet.
								<?php endif; ?>
								For other providers, add their IPs to the trusted networks file on the <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-opsec-ip-blocklist' ) ); ?>">IP Blocklist</a> page — that list is exempt here too.
							</p>
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
				</table>

				<?php submit_button( 'Save settings' ); ?>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
				<?php wp_nonce_field( 'wpopsec_qg_refresh_xmlrpc_allow' ); ?>
				<input type="hidden" name="action" value="wpopsec_qg_refresh_xmlrpc_allow">
				<?php submit_button( 'Refresh Jetpack IP list now', 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
	}
}
