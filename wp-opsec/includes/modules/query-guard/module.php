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

	public static function check_dest() {
		return WPOPSEC_CHECKS_DIR . '/query-guard.php';
	}

	public static function activate() {
		self::deploy_check_file();
	}

	public static function deactivate() {
		if ( file_exists( self::check_dest() ) ) {
			unlink( self::check_dest() );
		}
	}

	public static function register() {
		self::deploy_check_file();

		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_post_wpopsec_qg_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		return __CLASS__;
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

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$mode          = get_option( 'wpopsec_query_guard_mode', 'log' );
		$categories    = get_option( 'wpopsec_query_guard_categories', array_keys( self::CATEGORIES ) );
		$block_xmlrpc  = get_option( 'wpopsec_query_guard_block_xmlrpc', false );
		?>
		<div class="wrap">
			<h1>WP Opsec — Query Guard</h1>
			<p>Scans the GET query string of every request for common attack signatures (SQLi, XSS, path traversal, command injection). POST bodies are never inspected, to avoid false positives against legitimate content like the block editor.</p>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
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
		</div>
		<?php
	}
}
