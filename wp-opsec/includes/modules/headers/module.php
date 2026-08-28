<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Security response headers.
 *
 * Everything here is opt-in per header, because the two that can actually
 * break a site (HSTS, CSP) are exactly the two people most want. Defaults
 * enable only the headers that cannot break normal WordPress rendering.
 */
class WPOpsec_Module_Headers {

	/** id => [label, description, default, breaks-things?] */
	public static function definitions() {
		return array(
			'x_content_type_options' => array(
				'label'   => 'X-Content-Type-Options: nosniff',
				'desc'    => 'Stops browsers MIME-sniffing a response into a different content type. No practical downside.',
				'default' => true,
			),
			'x_frame_options'        => array(
				'label'   => 'X-Frame-Options: SAMEORIGIN',
				'desc'    => 'Blocks clickjacking via framing on other domains. Disable if you intentionally embed this site elsewhere.',
				'default' => true,
			),
			'referrer_policy'        => array(
				'label'   => 'Referrer-Policy: strict-origin-when-cross-origin',
				'desc'    => 'Stops full URLs (including paths) leaking to third-party sites in the Referer header.',
				'default' => true,
			),
			'permissions_policy'     => array(
				'label'   => 'Permissions-Policy: camera/microphone/geolocation off',
				'desc'    => 'Denies powerful browser APIs the site does not use.',
				'default' => true,
			),
			'hsts'                   => array(
				'label'   => 'Strict-Transport-Security (HSTS)',
				'desc'    => 'Forces HTTPS for future visits. Only enable once HTTPS works everywhere and you intend to keep it — browsers remember this and will refuse plain HTTP for the max-age duration.',
				'default' => false,
			),
			'csp'                    => array(
				'label'   => 'Content-Security-Policy',
				'desc'    => 'Restricts where scripts/styles can load from. Powerful but the most likely to break themes, page builders and embeds — start in report-only mode and read your browser console.',
				'default' => false,
			),
		);
	}

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_post_wpopsec_hdr_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_filter( 'wp_headers', array( __CLASS__, 'add_headers' ) );

		// wp_headers doesn't cover wp-admin or login screens; send there too.
		add_action( 'admin_init', array( __CLASS__, 'send_headers_directly' ) );
		add_action( 'login_init', array( __CLASS__, 'send_headers_directly' ) );

		return __CLASS__;
	}

	private static function enabled( $id ) {
		$saved = get_option( 'wpopsec_headers_enabled', null );
		if ( null === $saved ) {
			$defs = self::definitions();
			return ! empty( $defs[ $id ]['default'] );
		}
		return in_array( $id, (array) $saved, true );
	}

	/**
	 * Whether the *visitor's* connection is HTTPS.
	 *
	 * is_ssl() only sees the connection to PHP, so behind a reverse proxy
	 * that terminates TLS and forwards plain HTTP it returns false even
	 * though the browser is on HTTPS — which silently suppressed HSTS on
	 * exactly the setups most likely to want it. X-Forwarded-Proto is only
	 * consulted when the admin has confirmed the site is behind a trusted
	 * proxy, because that header is attacker-controlled otherwise.
	 */
	public static function request_is_https() {
		if ( is_ssl() ) {
			return true;
		}

		if ( ! get_option( 'wpopsec_headers_behind_proxy', false ) ) {
			return false;
		}

		$proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
		if ( '' !== $proto ) {
			// May be a comma-separated chain; the first entry is the client.
			$first = trim( strtok( $proto, ',' ) );
			return 0 === strcasecmp( 'https', $first );
		}

		if ( isset( $_SERVER['HTTP_X_FORWARDED_SSL'] ) && 'on' === strtolower( $_SERVER['HTTP_X_FORWARDED_SSL'] ) ) {
			return true;
		}

		return false;
	}

	/** @return array<string,string> header => value */
	public static function build() {
		$headers = array();

		if ( self::enabled( 'x_content_type_options' ) ) {
			$headers['X-Content-Type-Options'] = 'nosniff';
		}
		if ( self::enabled( 'x_frame_options' ) ) {
			$headers['X-Frame-Options'] = 'SAMEORIGIN';
		}
		if ( self::enabled( 'referrer_policy' ) ) {
			$headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
		}
		if ( self::enabled( 'permissions_policy' ) ) {
			$headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()';
		}

		// Only meaningful over HTTPS, and actively harmful to send otherwise
		// (a browser that sees it on a working HTTP-only site will pin HTTPS
		// and the site becomes unreachable).
		if ( self::enabled( 'hsts' ) && self::request_is_https() ) {
			$max_age  = max( 0, (int) get_option( 'wpopsec_headers_hsts_max_age', 15552000 ) );
			$value    = 'max-age=' . $max_age;
			if ( get_option( 'wpopsec_headers_hsts_subdomains', false ) ) {
				$value .= '; includeSubDomains';
			}
			if ( get_option( 'wpopsec_headers_hsts_preload', false ) ) {
				$value .= '; preload';
			}
			$headers['Strict-Transport-Security'] = $value;
		}

		if ( self::enabled( 'csp' ) ) {
			$policy = trim( (string) get_option( 'wpopsec_headers_csp_policy', '' ) );
			if ( '' !== $policy ) {
				$header = get_option( 'wpopsec_headers_csp_report_only', true )
					? 'Content-Security-Policy-Report-Only'
					: 'Content-Security-Policy';
				$headers[ $header ] = $policy;
			}
		}

		return $headers;
	}

	public static function add_headers( $headers ) {
		return array_merge( (array) $headers, self::build() );
	}

	public static function send_headers_directly() {
		if ( headers_sent() ) {
			return;
		}
		foreach ( self::build() as $name => $value ) {
			header( "{$name}: {$value}" );
		}
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'Security Headers',
			'Security Headers',
			'manage_options',
			'wp-opsec-headers',
			array( __CLASS__, 'render_settings_page' )
		);
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_hdr_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$posted  = isset( $_POST['headers'] ) ? (array) wp_unslash( $_POST['headers'] ) : array();
		$enabled = array_values( array_intersect( $posted, array_keys( self::definitions() ) ) );
		update_option( 'wpopsec_headers_enabled', $enabled );

		update_option( 'wpopsec_headers_hsts_max_age', max( 0, (int) ( $_POST['hsts_max_age'] ?? 15552000 ) ) );
		update_option( 'wpopsec_headers_hsts_subdomains', isset( $_POST['hsts_subdomains'] ) );
		update_option( 'wpopsec_headers_hsts_preload', isset( $_POST['hsts_preload'] ) );
		update_option( 'wpopsec_headers_behind_proxy', isset( $_POST['behind_proxy'] ) );

		update_option( 'wpopsec_headers_csp_report_only', isset( $_POST['csp_report_only'] ) );
		$policy = isset( $_POST['csp_policy'] ) ? trim( wp_unslash( $_POST['csp_policy'] ) ) : '';
		// Header values can't contain newlines — a CR/LF here would be a
		// response-splitting bug, so flatten before storing.
		update_option( 'wpopsec_headers_csp_policy', preg_replace( '/[\r\n]+/', ' ', $policy ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$defs    = self::definitions();
		$current = self::build();
		?>
		<div class="wrap">
			<h1>WP Opsec — Security Headers</h1>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>

			<h2>Currently sent</h2>
			<?php if ( empty( $current ) ) : ?>
				<p>No security headers are being sent.</p>
			<?php else : ?>
				<table class="widefat" style="max-width:800px">
					<?php foreach ( $current as $name => $value ) : ?>
						<tr><th style="width:280px"><?php echo esc_html( $name ); ?></th><td><code><?php echo esc_html( $value ); ?></code></td></tr>
					<?php endforeach; ?>
				</table>
			<?php endif; ?>
			<?php if ( self::enabled( 'hsts' ) && ! self::request_is_https() ) : ?>
				<div class="notice notice-warning inline">
					<p>HSTS is enabled but this request isn't recognised as HTTPS, so the header is being withheld — sending it over plain HTTP would pin browsers to a scheme the site may not serve.</p>
					<?php if ( ! get_option( 'wpopsec_headers_behind_proxy', false ) && ! empty( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) : ?>
						<p><strong>This request arrived with <code>X-Forwarded-Proto: <?php echo esc_html( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) ); ?></code></strong>, which suggests a reverse proxy is terminating TLS. Tick the proxy option below to have HSTS honour it.</p>
					<?php endif; ?>
				</div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_hdr_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_hdr_save_settings">

				<table class="form-table">
					<tr>
						<th>Headers</th>
						<td>
							<?php foreach ( $defs as $id => $def ) : ?>
								<label style="display:block;margin-bottom:.6em">
									<input type="checkbox" name="headers[]" value="<?php echo esc_attr( $id ); ?>" <?php checked( self::enabled( $id ) ); ?>>
									<strong><?php echo esc_html( $def['label'] ); ?></strong><br>
									<span class="description" style="margin-left:1.8em"><?php echo esc_html( $def['desc'] ); ?></span>
								</label>
							<?php endforeach; ?>
						</td>
					</tr>
					<tr>
						<th>HSTS options</th>
						<td>
							max-age <input type="number" name="hsts_max_age" value="<?php echo esc_attr( (int) get_option( 'wpopsec_headers_hsts_max_age', 15552000 ) ); ?>" min="0" style="width:9em"> seconds
							<p style="margin:.4em 0"><label><input type="checkbox" name="hsts_subdomains" <?php checked( get_option( 'wpopsec_headers_hsts_subdomains', false ) ); ?>> includeSubDomains</label></p>
							<p style="margin:.4em 0"><label><input type="checkbox" name="hsts_preload" <?php checked( get_option( 'wpopsec_headers_hsts_preload', false ) ); ?>> preload</label></p>
							<p style="margin:.4em 0"><label><input type="checkbox" name="behind_proxy" <?php checked( get_option( 'wpopsec_headers_behind_proxy', false ) ); ?>> This site is behind a reverse proxy that terminates HTTPS</label></p>
							<p class="description">
								Only sent on HTTPS requests. <code>preload</code> submits to a browser-baked list that is slow and awkward to reverse — don't set it casually.
								<br>Tick the proxy box if TLS ends at nginx/Cloudflare/a load balancer and PHP is served plain HTTP — otherwise <code>is_ssl()</code> is false and HSTS is never sent. Only tick it when a proxy really is in front, since <code>X-Forwarded-Proto</code> can be forged by anyone able to reach the backend directly.
							</p>
						</td>
					</tr>
					<tr>
						<th><label for="wpopsec_csp">CSP policy</label></th>
						<td>
							<textarea id="wpopsec_csp" name="csp_policy" rows="4" cols="70" placeholder="default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline'"><?php echo esc_textarea( (string) get_option( 'wpopsec_headers_csp_policy', '' ) ); ?></textarea>
							<p><label><input type="checkbox" name="csp_report_only" <?php checked( get_option( 'wpopsec_headers_csp_report_only', true ) ); ?>> Report-only (log violations, don't enforce)</label></p>
							<p class="description">Leave report-only until your browser console shows no violations on the front end <em>and</em> in wp-admin.</p>
						</td>
					</tr>
				</table>

				<?php submit_button( 'Save settings' ); ?>
			</form>
		</div>
		<?php
	}
}
