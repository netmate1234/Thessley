<?php
/**
 * Plugin Name: ShieldCore Security
 * Description: General security hardening plugin. Modular — each feature lives under includes/modules.
 * Version: 1.0.10
 * Author: Martin Lundstrom
 * Text Domain: shieldcore-security
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SHIELDCORE_VERSION', '1.0.10' );
define( 'SHIELDCORE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'SHIELDCORE_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'SHIELDCORE_MU_SOURCE', SHIELDCORE_PLUGIN_DIR . 'mu-loader/wp-shieldcore-early.php' );
define( 'SHIELDCORE_MU_DEST', WPMU_PLUGIN_DIR . '/wp-shieldcore-early.php' );
define( 'SHIELDCORE_CHECKS_DIR', WPMU_PLUGIN_DIR . '/wp-shieldcore-checks' );

require_once SHIELDCORE_PLUGIN_DIR . 'includes/class-ui.php';
require_once SHIELDCORE_PLUGIN_DIR . 'includes/class-module-loader.php';
require_once SHIELDCORE_PLUGIN_DIR . 'includes/class-menu-router.php';

register_activation_hook( __FILE__, array( 'ShieldCore_Module_Loader', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'ShieldCore_Module_Loader', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'ShieldCore_Module_Loader', 'init' ) );
