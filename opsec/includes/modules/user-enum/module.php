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
		add_action( 'admin_post_wpopsec_ue_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		if ( get_option( 'wpopsec_user_enum_block_author_scan', true ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'block_author_scan' ) );
		}
		if ( get_option( 'wpopsec_user_enum_block_rest_users', true ) ) {
			add_filter( 'rest_request_before_callbacks', array( __CLASS__, 'block_rest_users' ), 20, 3 );
			add_filter( 'rest_endpoints', array( __CLASS__, 'remove_user_endpoints' ) );
		}
		if ( get_option( 'wpopsec_user_enum_disable_oembed_author', true ) ) {
			add_filter( 'oembed_response_data', array( __CLASS__, 'strip_oembed_author' ) );
		}
		if ( get_option( 'wpopsec_user_enum_hide_user_sitemap', true ) ) {
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'remove_user_sitemap_provider' ), 10, 2 );
			add_action( 'template_redirect', array( __CLASS__, 'block_user_sitemap_request' ), 1 );
		}

		return __CLASS__;
	}

	/**
	 * WordPress's own Sitemaps API (core since 5.5) registers a "users"
	 * provider by default, listing every account with public content at
	 * /wp-sitemap-users-1.xml — the exact same disclosure ?author=N
	 * probing and the REST users endpoint above both exist to stop, just
	 * via a URL those checks never touch. Unregistering the provider is
	 * WordPress core's own documented way to remove it, and is normally
	 * sufficient on its own.
	 */
	public static function remove_user_sitemap_provider( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * Belt-and-suspenders alongside the filter above: once "users" is
	 * unregistered, what WordPress core does with a request for it isn't
	 * reliable — confirmed live, not theoretical, that redirect_canonical()
	 * can step in and "helpfully" guess-redirect to an unrelated real page
	 * at 200 instead of a clean 404, since it fires on the very same
	 * hook and its whole purpose is guessing a replacement for exactly
	 * this kind of unrecognized URL. Priority 1 and an outright exit — not
	 * set_404() and letting WordPress's own template flow continue — is
	 * the only way to guarantee redirect_canonical() (default priority 10
	 * on this same hook) never gets a turn, matching how xmlrpc_access
	 * handles its own block below rather than trusting wp_die()'s usual
	 * behavior. Catches both the pretty-permalink URL and the plain
	 * query-var form (?sitemap=users) sites without rewrite rules use.
	 */
	public static function block_user_sitemap_request() {
		$is_users_sitemap = 'users' === get_query_var( 'sitemap' )
			|| (bool) preg_match( '#/wp-sitemap-users-\d+\.xml(?:$|[/?])#i', (string) ( $_SERVER['REQUEST_URI'] ?? '' ) );

		if ( ! $is_users_sitemap ) {
			return;
		}

		status_header( 404 );
		nocache_headers();
		exit;
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
		if ( wpopsec_ip_is_exempt( wpopsec_client_ip() ) ) {
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
	 * Dedicated user/customer/student-listing REST routes — core's own
	 * /wp/v2/users plus the equivalent endpoint several popular plugins
	 * register. Real attack traffic (logged on this exact site) hitting
	 * wc/v1/customers, ldlms/v1/users, tutor/v1/students,
	 * ultimate-member/v1/users, and bbp-api/v1/users was going completely
	 * unblocked, since the original check only ever matched core's own
	 * route. Each of these exists purely to enumerate people — there's no
	 * legitimate anonymous use case for listing every customer/student/
	 * member via a public API, so the same authenticated-only gate core's
	 * own endpoint gets carries the same low false-positive risk here.
	 *
	 * Deliberately NOT extended to generic content endpoints (wp/v2/posts,
	 * wp/v2/comments, wp/v2/media) even though a _fields=author-only query
	 * against them can enumerate identity too — those have real legitimate
	 * anonymous uses (public comment listings, post embeds), and reliably
	 * telling "cherry-picking only author fields" apart from "a normal
	 * request that happens to include one" needs more careful heuristic
	 * design than a route allowlist, not a quick addition here.
	 */
	private static function enum_route_patterns() {
		return array(
			'#^/wp/v2/users(/|$)#',
			'#^/wc/v[1-3]/customers(/|$)#',          // WooCommerce
			'#^/ldlms/v[12]/users(/|$)#',             // LearnDash
			'#^/tutor/v1/students(/|$)#',             // Tutor LMS
			'#^/ultimate-member/v[12]/users(/|$)#',   // Ultimate Member
			'#^/bbp-api/v1/users(/|$)#',               // bbPress API
		);
	}

	/**
	 * Matches on the resolved REST route rather than REQUEST_URI: a raw
	 * substring test also fired on ordinary front-end URLs that merely
	 * contained "/wp/v2/users" (a post permalink about the REST API, a
	 * redirect parameter), 401-ing pages that had nothing to do with the
	 * users endpoint.
	 *
	 * @param mixed            $response
	 * @param array|object     $handler
	 * @param WP_REST_Request  $request
	 */
	public static function block_rest_users( $response, $handler, $request ) {
		if ( is_wp_error( $response ) || self::viewer_may_list_users() ) {
			return $response;
		}
		if ( wpopsec_ip_is_exempt( wpopsec_client_ip() ) ) {
			return $response;
		}

		if ( ! $request instanceof WP_REST_Request ) {
			return $response;
		}

		$route = (string) $request->get_route();

		// /users/me is the caller's own record and needs authentication
		// anyway — it leaks nothing about other accounts. Scoped to core's
		// own route only: the other plugins above don't necessarily share
		// this convention, and guessing wrong risks under-blocking them.
		if ( preg_match( '#^/wp/v2/users/me(/|$)#', $route ) ) {
			return $response;
		}

		$matched = false;
		foreach ( self::enum_route_patterns() as $pattern ) {
			if ( preg_match( $pattern, $route ) ) {
				$matched = true;
				break;
			}
		}
		if ( ! $matched ) {
			return $response;
		}

		wpopsec_log_event( 'user-enum', 'rest_users', 'blocked', 'anonymous REST user/customer listing: ' . $route );

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


	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_ue_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'wpopsec_user_enum_block_author_scan', isset( $_POST['block_author_scan'] ) );
		update_option( 'wpopsec_user_enum_block_rest_users', isset( $_POST['block_rest_users'] ) );
		update_option( 'wpopsec_user_enum_disable_oembed_author', isset( $_POST['disable_oembed_author'] ) );
		update_option( 'wpopsec_user_enum_hide_user_sitemap', isset( $_POST['hide_user_sitemap'] ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		WPOpsec_UI::open( 'user-enum' );

		if ( isset( $_GET['saved'] ) ) {
			WPOpsec_UI::notice( 'success', 'Settings saved.' );
		}
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wpopsec_ue_save_settings' ); ?>
			<input type="hidden" name="action" value="wpopsec_ue_save_settings">

			<?php WPOpsec_UI::section( 'What to block', 'hidden' ); ?>

				<?php
				WPOpsec_UI::row(
					'Author scans',
					function () {
						?>
						<label><input type="checkbox" name="block_author_scan" <?php checked( get_option( 'wpopsec_user_enum_block_author_scan', true ) ); ?>> Block <code>?author=1</code> probes</label>
						<?php
					},
					'WordPress redirects the numeric form to <code>/author/&lt;login-name&gt;/</code>, which reveals the account name. Normal author archive URLs still work.'
				);

				WPOpsec_UI::row(
					'REST API',
					function () {
						?>
						<label><input type="checkbox" name="block_rest_users" <?php checked( get_option( 'wpopsec_user_enum_block_rest_users', true ) ); ?>> Require authentication for <code>/wp-json/wp/v2/users</code></label>
						<?php
					},
					'By default this endpoint lists every account with a published post, to anyone. <code>/users/me</code> is left alone. Disable if a headless front end reads it anonymously.'
				);

				WPOpsec_UI::row(
					'oEmbed',
					function () {
						?>
						<label><input type="checkbox" name="disable_oembed_author" <?php checked( get_option( 'wpopsec_user_enum_disable_oembed_author', true ) ); ?>> Strip author details from oEmbed responses</label>
						<?php
					},
					'oEmbed output includes <code>author_name</code> and <code>author_url</code> for any public post.'
				);

				WPOpsec_UI::row(
					'User sitemap',
					function () {
						?>
						<label><input type="checkbox" name="hide_user_sitemap" <?php checked( get_option( 'wpopsec_user_enum_hide_user_sitemap', true ) ); ?>> Remove <code>/wp-sitemap-users-1.xml</code></label>
						<?php
					},
					'WordPress\'s built-in Sitemaps API lists every account with public content here by default, same disclosure as <code>?author=N</code> probing — just a URL those checks never touch. Post and page sitemaps are unaffected.'
				);
				?>

			<?php WPOpsec_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		WPOpsec_UI::close();
	}
}
