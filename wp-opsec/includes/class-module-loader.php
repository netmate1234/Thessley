<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Discovers and wires up modules under includes/modules/*.
 * Each module dir has a module.php defining a class WPOpsec_Module_<Name>
 * with static activate(), deactivate(), register() methods.
 */
class WPOpsec_Module_Loader {

	/** @var array<string,string> module directory name => class name, in load order */
	private static $modules = array(
		'ip-blocklist' => 'WPOpsec_Module_IP_Blocklist',
		'query-guard'  => 'WPOpsec_Module_Query_Guard',
	);

	public static function init() {
		self::ensure_mu_loader_current();

		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ), 5 );

		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'register' ) ) {
				call_user_func( array( $class, 'register' ) );
			}
		}
	}

	public static function activate() {
		self::copy_mu_loader();

		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'activate' ) ) {
				call_user_func( array( $class, 'activate' ) );
			}
		}
	}

	public static function deactivate() {
		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'deactivate' ) ) {
				call_user_func( array( $class, 'deactivate' ) );
			}
		}

		self::remove_mu_loader();
	}

	public static function admin_menu() {
		add_menu_page(
			'WP Opsec',
			'WP Opsec',
			'manage_options',
			'wp-opsec',
			array( __CLASS__, 'render_dashboard' ),
			'dashicons-shield'
		);
	}

	public static function render_dashboard() {
		echo '<div class="wrap"><h1>WP Opsec</h1><p>Security modules are listed in the submenu.</p></div>';
	}

	private static function load_module( $module ) {
		$file = WPOPSEC_PLUGIN_DIR . "includes/modules/{$module}/module.php";
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}

	private static function copy_mu_loader() {
		if ( ! file_exists( WPMU_PLUGIN_DIR ) ) {
			wp_mkdir_p( WPMU_PLUGIN_DIR );
		}
		copy( WPOPSEC_MU_SOURCE, WPOPSEC_MU_DEST );
	}

	private static function remove_mu_loader() {
		if ( file_exists( WPOPSEC_MU_DEST ) ) {
			unlink( WPOPSEC_MU_DEST );
		}
	}

	/**
	 * Keep the deployed mu-plugin file in sync with the version shipped in
	 * this plugin (e.g. after a plugin update), without requiring reactivation.
	 */
	private static function ensure_mu_loader_current() {
		if ( ! file_exists( WPOPSEC_MU_DEST )
			|| md5_file( WPOPSEC_MU_DEST ) !== md5_file( WPOPSEC_MU_SOURCE ) ) {
			self::copy_mu_loader();
		}
	}
}
