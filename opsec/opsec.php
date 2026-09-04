<?php
/**
 * Plugin Name: Opsec
 * Description: General security hardening plugin. Modular — each feature lives under includes/modules.
 * Version: 0.1.8
 * Author: Martin Lundstrom
 * Text Domain: opsec
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPOPSEC_VERSION', '0.1.1' );
define( 'WPOPSEC_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPOPSEC_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WPOPSEC_MU_SOURCE', WPOPSEC_PLUGIN_DIR . 'mu-loader/wp-opsec-early.php' );
define( 'WPOPSEC_MU_DEST', WPMU_PLUGIN_DIR . '/wp-opsec-early.php' );
define( 'WPOPSEC_CHECKS_DIR', WPMU_PLUGIN_DIR . '/wp-opsec-checks' );

require_once WPOPSEC_PLUGIN_DIR . 'includes/class-ui.php';
require_once WPOPSEC_PLUGIN_DIR . 'includes/class-module-loader.php';
require_once WPOPSEC_PLUGIN_DIR . 'includes/class-menu-router.php';

register_activation_hook( __FILE__, array( 'WPOpsec_Module_Loader', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WPOpsec_Module_Loader', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'WPOpsec_Module_Loader', 'init' ) );
