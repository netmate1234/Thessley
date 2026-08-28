<?php
/**
 * WP Opsec — early request gate.
 *
 * Deployed as a must-use plugin so it runs before the rest of WordPress
 * bootstraps. Self-contained: does not depend on the main wp-opsec plugin
 * being loaded (mu-plugins load first). Modules drop individual check
 * files into wp-content/mu-plugins/wp-opsec-checks/*.php; each such file
 * calls wpopsec_register_check() to add itself.
 *
 * Kill switch: define('WPOPSEC_DISABLE', true) in wp-config.php to bypass
 * everything below if a check ever misfires.
 */

if ( defined( 'WPOPSEC_DISABLE' ) && WPOPSEC_DISABLE ) {
	return;
}

// CLI/cron has no real "visitor" and REMOTE_ADDR is unreliable there
// (often unset or a loopback placeholder) — never gate it, only HTTP requests.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	return;
}

if ( ! function_exists( 'wpopsec_register_check' ) ) {
	/**
	 * @param callable $check Receives no args, returns null/false to allow,
	 *                        or array{reason:string} to block the request.
	 */
	function wpopsec_register_check( callable $check ) {
		global $wpopsec_checks;
		$wpopsec_checks[] = $check;
	}

	function wpopsec_client_ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
	}
}

$GLOBALS['wpopsec_checks'] = array();

$checks_dir = WPMU_PLUGIN_DIR . '/wp-opsec-checks';
foreach ( glob( $checks_dir . '/*.php' ) ?: array() as $check_file ) {
	require $check_file;
}

foreach ( $GLOBALS['wpopsec_checks'] as $check ) {
	$result = call_user_func( $check );
	if ( is_array( $result ) ) {
		wp_die(
			esc_html( $result['reason'] ?? 'Forbidden' ),
			'403 Forbidden',
			array( 'response' => 403 )
		);
	}
}
