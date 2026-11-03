<?php
/**
 * Plugin Name: Thessley Passkey
 * Description: Passwordless WordPress sign-in with the Thessley Passkey Android app — scan a QR code or tap a link, confirmed with the phone's own biometric lock.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 8.3
 * Author: Martin Lundstrom
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: thessley-passkey
 *
 * This plugin is the server half of the Thessley Passkey protocol. It was
 * split out of Thessley Security Hardening so the two can be installed,
 * updated and reviewed independently: the passkey code has no dependency on
 * the hardening modules, and the hardening plugin no longer ships it.
 *
 * It reuses the same database tables and options the module used
 * (wp_thessley_passkeys, wp_thessley_passkey_requests, thessley_passkey_mode,
 * thessley_passkey_identify), so an existing install keeps every enrolled
 * device and its settings when it moves over.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'THESSLEY_PASSKEY_VERSION', '1.0.0' );
define( 'THESSLEY_PASSKEY_FILE', __FILE__ );
define( 'THESSLEY_PASSKEY_DIR', plugin_dir_path( __FILE__ ) );
define( 'THESSLEY_PASSKEY_URL', plugin_dir_url( __FILE__ ) );

require_once THESSLEY_PASSKEY_DIR . 'includes/class-store.php';
require_once THESSLEY_PASSKEY_DIR . 'includes/class-crypto.php';
require_once THESSLEY_PASSKEY_DIR . 'includes/class-attestation.php';
require_once THESSLEY_PASSKEY_DIR . 'includes/class-tpm.php';
require_once THESSLEY_PASSKEY_DIR . 'includes/class-ui.php';
require_once THESSLEY_PASSKEY_DIR . 'includes/class-login.php';

register_activation_hook( __FILE__, array( 'Thessley_Passkey_Login', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Thessley_Passkey_Login', 'deactivate' ) );

add_action(
	'plugins_loaded',
	static function () {
		Thessley_Passkey_Login::register();
	}
);

/**
 * One top-level menu entry, next to Comments. The settings screen is the
 * plugin's own render_page(); nothing here registers under another plugin.
 */
add_action(
	'admin_menu',
	static function () {
		add_menu_page(
			'Thessley Passkey',
			'Thessley Passkey',
			'manage_options',
			'thessley-passkey',
			array( 'Thessley_Passkey_Login', 'render_page' ),
			'dashicons-smartphone',
			26
		);
	}
);

/**
 * The admin stylesheet (badges, cards) is shared with the profile-page device
 * list, which enqueues the same handle itself.
 */
add_action(
	'admin_enqueue_scripts',
	static function ( $hook ) {
		if ( 'toplevel_page_thessley-passkey' !== $hook ) {
			return;
		}
		$css_path = THESSLEY_PASSKEY_DIR . 'assets/admin.css';
		$css_ver  = file_exists( $css_path ) ? (string) filemtime( $css_path ) : THESSLEY_PASSKEY_VERSION;
		wp_enqueue_style( 'thessley-admin', THESSLEY_PASSKEY_URL . 'assets/admin.css', array(), $css_ver );
	}
);
