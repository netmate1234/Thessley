<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Blocks the standard ways an anonymous visitor can enumerate valid
 * usernames. Knowing a real username turns a brute-force from "guess two
 * things" into "guess one", so this pairs directly with login-guard.
 *
 * All checks bail for logged-in users with list_users — the REST users
 * endpoint and author archives are legitimately used by the editor.
 */
class WPOpsec_Module_User_Enum {

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_post_wpopsec_ue_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		if ( get_option( 'wpopsec_user_enum_block_author_scan', true ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'block_author_scan' ) );
		}
		if ( get_option( 'wpopsec_user_enum_block_rest_users', true ) ) {
			add_filter( 'rest_authentication_errors', array( __CLASS__, 'block_rest_users' ), 20 );
			add_filter( 'rest_endpoints', array( __CLASS__, 'remove_user_endpoints' ) );
		}
		if ( get_option( 'wpopsec_user_enum_disable_oembed_author', true ) ) {
			add_filter( 'oembed_response_data', array( __CLASS__, 'strip_oembed_author' ) );
		}

		return __CLASS__;
	}

	private static function viewer_may_list_users() {
		return is_user_logged_in() && current_user_can( 'list_users' );
	}

	/**
	 * /?author=1 redirects to /author/<slug>/, handing out the login name.
	 * Block the numeric form for anonymous visitors; the pretty author
	 * archive itself still works, since that's a normal published URL.
	 */
	public static function block_author_scan() {
		if ( self::viewer_may_list_users() ) {
			return;
		}
		if ( ! isset( $_GET['author'] ) ) {
			return;
		}
		if ( ! preg_match( '/^\d+$/', (string) wp_unslash( $_GET['author'] ) ) ) {
			return;
		}

		wpopsec_log_event( 'user-enum', 'author_scan', 'blocked', 'numeric ?author= probe' );

		status_header( 403 );
		nocache_headers();
		wp_die( 'Access denied.', '403 Forbidden', array( 'response' => 403 ) );
	}

	/**
	 * /wp-json/wp/v2/users lists every account with a published post,
	 * including slugs, to anonymous callers by default.
	 */
	public static function block_rest_users( $result ) {
		if ( ! empty( $result ) || self::viewer_may_list_users() ) {
			return $result;
		}

		$route = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( false === strpos( $route, '/wp/v2/users' ) ) {
			return $result;
		}

		wpopsec_log_event( 'user-enum', 'rest_users', 'blocked', 'anonymous REST users query' );

		return new WP_Error(
			'wpopsec_rest_users_forbidden',
			__( 'Authentication required.', 'wp-opsec' ),
			array( 'status' => 401 )
		);
	}

	/** Belt-and-braces: unregister the routes so they 404 rather than 401. */
	public static function remove_user_endpoints( $endpoints ) {
		if ( self::viewer_may_list_users() ) {
			return $endpoints;
		}
		unset( $endpoints['/wp/v2/users'] );
		unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		return $endpoints;
	}

	/** oEmbed responses include author_name/author_url for any public post. */
	public static function strip_oembed_author( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'User Enumeration',
			'User Enumeration',
			'manage_options',
			'wp-opsec-user-enum',
			array( __CLASS__, 'render_settings_page' )
		);
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_ue_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'wpopsec_user_enum_block_author_scan', isset( $_POST['block_author_scan'] ) );
		update_option( 'wpopsec_user_enum_block_rest_users', isset( $_POST['block_rest_users'] ) );
		update_option( 'wpopsec_user_enum_disable_oembed_author', isset( $_POST['disable_oembed_author'] ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		?>
		<div class="wrap">
			<h1>WP Opsec — User Enumeration</h1>
			<p>Stops anonymous visitors harvesting valid usernames. Logged-in users who can list users are unaffected, so the editor and admin screens keep working.</p>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_ue_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_ue_save_settings">

				<table class="form-table">
					<tr>
						<th>Author scans</th>
						<td>
							<label><input type="checkbox" name="block_author_scan" <?php checked( get_option( 'wpopsec_user_enum_block_author_scan', true ) ); ?>> Block <code>?author=1</code> probes</label>
							<p class="description">WordPress redirects the numeric form to <code>/author/&lt;login-name&gt;/</code>, which reveals the account name. Normal author archive URLs still work.</p>
						</td>
					</tr>
					<tr>
						<th>REST API</th>
						<td>
							<label><input type="checkbox" name="block_rest_users" <?php checked( get_option( 'wpopsec_user_enum_block_rest_users', true ) ); ?>> Require authentication for <code>/wp-json/wp/v2/users</code></label>
							<p class="description">By default this endpoint lists every account with a published post, to anyone. Disable if a headless front end or integration reads it anonymously.</p>
						</td>
					</tr>
					<tr>
						<th>oEmbed</th>
						<td>
							<label><input type="checkbox" name="disable_oembed_author" <?php checked( get_option( 'wpopsec_user_enum_disable_oembed_author', true ) ); ?>> Strip author details from oEmbed responses</label>
						</td>
					</tr>
				</table>

				<?php submit_button( 'Save settings' ); ?>
			</form>
		</div>
		<?php
	}
}
