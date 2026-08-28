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

		// POST scanning can't run in the early gate: it needs
		// is_user_logged_in(), which depends on pluggable.php, not loaded at
		// mu-plugin time. It hooks `init` rather than `plugins_loaded`
		// because register() is itself called during plugins_loaded — a
		// callback added there would be scheduled at a priority that has
		// already passed and would silently never run. `init` still fires
		// before request routing, admin-ajax handlers and REST dispatch.
		if ( get_option( 'wpopsec_query_guard_scan_post', true ) ) {
			add_action( 'init', array( __CLASS__, 'scan_request_body' ), 0 );
		}

		return __CLASS__;
	}

	/**
	 * Patterns for request bodies. Deliberately much narrower than the
	 * query-string set: no XSS/SQLi signatures here, because legitimate
	 * content genuinely contains those strings. These target code execution,
	 * file inclusion and upload abuse — things that have no business in a
	 * form submission from a visitor.
	 */
	private static function body_patterns() {
		return array(
			array( 'id' => 'body_php_open_tag', 'regex' => '/<\?php\b/i' ),
			array( 'id' => 'body_php_wrapper', 'regex' => '#\b(php|data|expect|phar)://#i' ),
			array( 'id' => 'body_eval_exec', 'regex' => '/\b(eval|assert|create_function|shell_exec|passthru|proc_open|popen|system)\s*\(/i' ),
			array( 'id' => 'body_base64_payload', 'regex' => '/base64_decode\s*\(/i' ),
			array( 'id' => 'body_traversal', 'regex' => '#\.\./\.\./#' ),
			array( 'id' => 'body_null_byte', 'regex' => '/%00|\x00/' ),
		);
	}

	/** Executable extensions that should never arrive via an upload field. */
	private static function dangerous_upload_regex() {
		return '/\.(php[0-9]?|phtml|phps|phar|pht|shtml|cgi|pl|py|jsp|asp|aspx|htaccess)(\.|$)/i';
	}

	public static function scan_request_body() {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) && 'PUT' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}

		$ip = wpopsec_client_ip();
		if ( '' !== $ip && wpopsec_ip_is_exempt( $ip ) ) {
			return;
		}

		// Authenticated users legitimately post PHP-ish content: the block
		// editor, code snippet plugins, support forms. Unauthenticated POST is
		// where the bulk of exploitable plugin bugs are actually reached, so
		// that's the default scope. Checked with a real cookie validation,
		// not just cookie presence, so a forged cookie can't opt out of it.
		if ( 'all' !== get_option( 'wpopsec_query_guard_post_scope', 'anon' ) ) {
			if ( is_user_logged_in() ) {
				return;
			}
		}

		$hit = self::find_body_hit();
		if ( ! $hit ) {
			return;
		}

		$mode = get_option( 'wpopsec_query_guard_mode', 'log' );

		if ( 'block' !== $mode ) {
			wpopsec_log_event( 'query-guard', $hit['id'], 'logged', $hit['detail'] );
			return;
		}

		wpopsec_log_event( 'query-guard', $hit['id'], 'blocked', $hit['detail'] );

		if ( '' !== $ip ) {
			wpopsec_local_blocklist_add( $ip, "query-guard: {$hit['id']}" );
		}

		status_header( 403 );
		nocache_headers();
		wp_die( 'Access denied.', '403 Forbidden', array( 'response' => 403 ) );
	}

	/** @return array{id:string,detail:string}|null */
	private static function find_body_hit() {
		// Uploaded filenames first — an executable extension arriving from an
		// anonymous visitor is about as unambiguous as a signal gets.
		foreach ( (array) $_FILES as $field => $file ) {
			foreach ( (array) ( is_array( $file['name'] ?? null ) ? $file['name'] : array( $file['name'] ?? '' ) ) as $name ) {
				if ( '' !== $name && preg_match( self::dangerous_upload_regex(), (string) $name ) ) {
					return array(
						'id'     => 'upload_executable_ext',
						'detail' => sprintf( 'field "%s" filename "%s"', $field, substr( (string) $name, 0, 100 ) ),
					);
				}
			}
		}

		$patterns = self::body_patterns();

		foreach ( self::flatten( $_POST ) as $key => $value ) {
			if ( ! is_string( $value ) || '' === $value ) {
				continue;
			}
			foreach ( $patterns as $p ) {
				if ( preg_match( $p['regex'], $value ) ) {
					return array(
						'id'     => $p['id'],
						'detail' => sprintf( 'field "%s": %s', $key, substr( preg_replace( '/\s+/', ' ', $value ), 0, 120 ) ),
					);
				}
			}
		}

		return null;
	}

	/** @return array<string,mixed> dot-joined key => scalar */
	private static function flatten( $data, $prefix = '', $depth = 0 ) {
		$out = array();
		if ( $depth > 6 ) {
			return $out;
		}
		foreach ( (array) $data as $k => $v ) {
			$key = '' === $prefix ? (string) $k : $prefix . '.' . $k;
			if ( is_array( $v ) ) {
				$out += self::flatten( $v, $key, $depth + 1 );
			} else {
				$out[ $key ] = $v;
			}
		}
		return $out;
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

		update_option( 'wpopsec_query_guard_scan_post', isset( $_POST['scan_post'] ) );
		$scope = sanitize_text_field( wp_unslash( $_POST['post_scope'] ?? 'anon' ) );
		update_option( 'wpopsec_query_guard_post_scope', in_array( $scope, array( 'anon', 'all' ), true ) ? $scope : 'anon' );

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
						<th>Request bodies (POST)</th>
						<td>
							<label><input type="checkbox" name="scan_post" <?php checked( get_option( 'wpopsec_query_guard_scan_post', true ) ); ?>> Scan POST data and file uploads</label>
							<p class="description">Uses a much narrower signature set than the query-string scan — code execution, file wrappers, traversal, and executable file uploads only. No XSS/SQLi patterns, since real content contains those strings.</p>
							<p style="margin:.5em 0 .2em">
								<label><input type="radio" name="post_scope" value="anon" <?php checked( get_option( 'wpopsec_query_guard_post_scope', 'anon' ), 'anon' ); ?>> Logged-out visitors only <em>(recommended)</em></label><br>
								<label><input type="radio" name="post_scope" value="all" <?php checked( get_option( 'wpopsec_query_guard_post_scope', 'anon' ), 'all' ); ?>> Everyone, including logged-in users</label>
							</p>
							<p class="description">43% of plugin vulnerabilities are exploitable without logging in, which is what the first option covers. Scanning logged-in POSTs as well will flag the block editor and any code-snippet plugin, so only pick that if you've confirmed it's quiet in log-only mode first.</p>
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
