<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Owns wpopsec_ip_allowlist — one list of IPv4 addresses that's exempt
 * from every blocking module, not just one. Used to live as a "Never-
 * block IPs" field on the IP Blocklist page, but it was only actually
 * being checked there and, separately, at local-blocklist escalation
 * time — Geo Blocker, Geo Login, Rate Limiter, Login Guard, and Query
 * Guard's signature scan all ignored it. Fixed at the source instead of
 * patching each one by hand: wpopsec_ip_is_exempt() (mu-loader) now
 * checks this list itself, and that's the one exemption check nearly
 * every blocking module already calls — so an entry here is honored
 * everywhere automatically, including any future module that follows
 * the same pattern.
 *
 * No check.php: this module doesn't gate anything itself, it just owns
 * the settings UI for data the early gate already reads directly.
 */
class WPOpsec_Module_Whitelist {

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_post_wpopsec_wl_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		return __CLASS__;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_wl_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$raw  = isset( $_POST['allowlist'] ) ? wp_unslash( $_POST['allowlist'] ) : '';
		$list = array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ) );
		$list = array_values(
			array_filter(
				$list,
				function ( $ip ) {
					return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
				}
			)
		);
		update_option( 'wpopsec_ip_allowlist', $list );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$allowlist = get_option( 'wpopsec_ip_allowlist', array() );

		WPOpsec_UI::open( 'whitelist' );

		if ( isset( $_GET['saved'] ) ) {
			WPOpsec_UI::notice( 'success', 'Settings saved.' );
		}

		WPOpsec_UI::tiles(
			array(
				array( 'icon' => 'yes-alt', 'tone' => 'quiet', 'value' => number_format_i18n( count( $allowlist ) ), 'label' => 'IPs whitelisted' ),
			)
		);

		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wpopsec_wl_save_settings' ); ?>
			<input type="hidden" name="action" value="wpopsec_wl_save_settings">

			<?php WPOpsec_UI::section( 'Never-block IPs', 'yes-alt' ); ?>
				<?php
				WPOpsec_UI::row(
					'IPs',
					function () use ( $allowlist ) {
						?>
						<textarea name="allowlist" rows="6" style="width:100%;max-width:420px" placeholder="203.0.113.7"><?php echo esc_textarea( implode( "\n", $allowlist ) ); ?></textarea>
						<?php
					},
					'One IPv4 per line. Exempt from every blocking module — IP Blocklist, Geo Blocker, Geo Login, Rate Limiter, Login Guard, Query Guard, User Enumeration — the same way your LAN and reserved IP space always are. Use this for your own address, a monitoring service, or anything else that should never be blocked no matter what triggers.'
				);
				?>
			<?php WPOpsec_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		WPOpsec_UI::close();
	}
}
