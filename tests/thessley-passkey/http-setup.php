<?php
/**
 * Prepares the HTTP flow test: one user with one enrolled EC-P256 device.
 * Run with: wp --path=<wordpress> eval-file tests/thessley-passkey/http-setup.php
 * Writes /tmp/opencode/pk-http.json for tests/thessley-passkey/http-flow.php.
 */

// Test scripts: run from WP-CLI or the command line, never from the web.
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) {
	exit;
}

wp_set_current_user( 1 );
require_once ABSPATH . 'wp-admin/includes/user.php';

$login = 'pk_http_alice';
$user  = get_user_by( 'login', $login );
if ( $user ) {
	$user_id = (int) $user->ID;
	wp_set_password( 'HttpTest123!', $user_id );
} else {
	$user_id = wp_insert_user(
		array(
			'user_login' => $login,
			'user_pass'  => 'HttpTest123!',
			'user_email' => 'pk_http_alice@example.test',
			'role'       => 'subscriber',
		)
	);
}

global $wpdb;
$wpdb->delete( Thessley_Passkey_Store::passkeys_table(), array( 'user_id' => $user_id ) );
$wpdb->delete( Thessley_Passkey_Store::requests_table(), array( 'requester_user_id' => $user_id ) );

// Clear short-lived state from a previous run so the rate limiter starts clean.
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_thessley_pk_rl_%' OR option_name LIKE '_transient_timeout_thessley_pk_rl_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_thessley_pk_bt_%' OR option_name LIKE '_transient_timeout_thessley_pk_bt_%'" );

$key = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
openssl_pkey_export( $key, $pem );
$details = openssl_pkey_get_details( $key );
$der     = base64_decode( preg_replace( '/-----[^-]+-----|\s+/', '', $details['key'] ) );

$credential = Thessley_Passkey_Store::add_passkey( $user_id, base64_encode( $der ), 'ES256', 'HTTP test phone' );

update_option( 'thessley_passkey_mode', 'optional' );
update_option( 'thessley_passkey_identify', 0 );

file_put_contents(
	'/tmp/opencode/pk-http.json',
	wp_json_encode(
		array(
			'user'       => $login,
			'user_id'    => $user_id,
			'credential' => $credential,
			'key_pem'    => $pem,
			'home'       => home_url(),
		)
	)
);

echo "HTTP test user ready: {$login} (#{$user_id}), credential " . substr( $credential, 0, 8 ) . "…\n";
