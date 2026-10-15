<?php
/**
 * Behavioural checks for the two-step revoke of a Passkey Login device: the
 * admin-post handler must refuse without (or with a wrong) password, rate-limit
 * wrong guesses, and only then revoke. Needs a real WordPress — run on a DEV site:
 *
 *   wp --path=/var/www/<dev-site> eval-file tests/passkey-login-revoke-checks.php
 *
 * Nothing leaves the box (outbound HTTP is short-circuited first) and every row,
 * user and transient it creates is removed again.
 */
add_filter( 'pre_http_request', function () { return new WP_Error( 'x', 'blocked in test' ); } );

require_once ABSPATH . 'wp-admin/includes/user.php';
global $wpdb;

$bad = 0;
$ok  = function ( $name, $cond ) use ( &$bad ) {
	echo ( $cond ? 'PASS ' : 'FAIL ' ) . $name . "\n";
	if ( ! $cond ) {
		++$bad;
	}
};

if ( ! defined( 'DOING_AJAX' ) ) {
	define( 'DOING_AJAX', true ); // wp_send_json_*() then goes through the ajax die handler we can intercept.
}
class Thessley_Test_Done extends Exception {}
add_filter( 'wp_die_ajax_handler', function () { return function () { throw new Thessley_Test_Done(); }; } );
add_filter( 'wp_die_handler', function () { return function () { throw new Thessley_Test_Done(); }; } );

/** Runs the real handler as $user_id with the given POST; returns [http status, decoded JSON]. */
$call = function ( $user_id, array $post ) {
	wp_set_current_user( $user_id );
	$_POST = $_REQUEST = $post;
	ob_start();
	try {
		Thessley_Module_Passkey_Login::handle_revoke();
	} catch ( Thessley_Test_Done $e ) {
		// expected: the handler ended the request
	}
	$out  = ob_get_clean();
	$json = json_decode( $out, true );
	// The HTTP status cannot be observed from the CLI (headers are already sent), so the JSON message is the signal.
	$code = ! empty( $json['success'] ) ? 200 : ( 'Too many wrong passwords. Try again in a few minutes.' === ( $json['data']['message'] ?? '' ) ? 429 : ( 'Forbidden.' === ( $json['data']['message'] ?? '' ) || 'Wrong password.' === ( $json['data']['message'] ?? '' ) ? 403 : 0 ) );
	return array( $code, $json );
};

$password = 'Correct-horse-9';
$owner    = wp_insert_user( array( 'user_login' => 'pkt_r1', 'user_pass' => $password, 'user_email' => 'pkt_r1@example.invalid', 'role' => 'subscriber' ) );
$other    = wp_insert_user( array( 'user_login' => 'pkt_r2', 'user_pass' => 'Other-pass-77', 'user_email' => 'pkt_r2@example.invalid', 'role' => 'subscriber' ) );
$admin    = wp_insert_user( array( 'user_login' => 'pkt_r3', 'user_pass' => 'Admin-pass-55', 'user_email' => 'pkt_r3@example.invalid', 'role' => 'administrator' ) );

$new_device = function ( $uid ) {
	$cred = Thessley_Passkey_Store::add_passkey( $uid, 'cHVi', 'ES256', 'zz-revoke-test' );
	return Thessley_Passkey_Store::get_passkey_row_id( $cred );
};
$active = function ( $row_id ) use ( $wpdb ) {
	return null === $wpdb->get_var( $wpdb->prepare( 'SELECT revoked_at FROM ' . Thessley_Passkey_Store::passkeys_table() . ' WHERE id = %d', $row_id ) )
		&& (bool) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM ' . Thessley_Passkey_Store::passkeys_table() . ' WHERE id = %d', $row_id ) );
};
$post = function ( $row_id, $uid, $extra = array() ) {
	wp_set_current_user( $uid );
	return array_merge( array( 'id' => $row_id, 'user_id' => $uid, '_wpnonce' => wp_create_nonce( 'thessley_pk_revoke_' . $row_id ) ), $extra );
};

$dev = $new_device( $owner );

[ $code, $json ] = $call( $owner, $post( $dev, $owner ) );
$ok( 'no password: refused (403), device still active', 403 === $code && false === $json['success'] && $active( $dev ) );

[ $code, $json ] = $call( $owner, $post( $dev, $owner, array( 'password' => 'wrong-one' ) ) );
$ok( 'wrong password: refused (403), device still active', 403 === $code && 'Wrong password.' === $json['data']['message'] && $active( $dev ) );

[ $code, $json ] = $call( $owner, $post( $dev, $owner, array( 'password' => $password ) ) );
$ok( 'right password: revoked', 200 === $code && true === $json['success'] && ! $active( $dev ) );

// Someone else's password never works for the owner's device.
$dev2 = $new_device( $owner );
[ $code ] = $call( $owner, $post( $dev2, $owner, array( 'password' => 'Other-pass-77' ) ) );
$ok( 'another account\'s password: refused', 403 === $code && $active( $dev2 ) );

// A user may not revoke somebody else's device at all, whatever the password.
[ $code ] = $call( $other, array_merge( $post( $dev2, $other ), array( 'user_id' => $owner, '_wpnonce' => wp_create_nonce( 'thessley_pk_revoke_' . $dev2 ), 'password' => 'Other-pass-77' ) ) );
$ok( 'another user cannot revoke it', 403 === $code && $active( $dev2 ) );

// An administrator can, with the ADMINISTRATOR\'s own password (not the owner\'s).
[ $code ] = $call( $admin, array_merge( $post( $dev2, $admin ), array( 'user_id' => $owner, '_wpnonce' => wp_create_nonce( 'thessley_pk_revoke_' . $dev2 ), 'password' => $password ) ) );
$ok( 'administrator with the owner\'s password: refused', 403 === $code && $active( $dev2 ) );
[ $code ] = $call( $admin, array_merge( $post( $dev2, $admin ), array( 'user_id' => $owner, '_wpnonce' => wp_create_nonce( 'thessley_pk_revoke_' . $dev2 ), 'password' => 'Admin-pass-55' ) ) );
$ok( 'administrator with their own password: revoked', 200 === $code && ! $active( $dev2 ) );

// Rate limit: five wrong guesses pause revoking, even for the right password.
$dev3 = $new_device( $owner );
delete_transient( 'thessley_pk_reauth_' . $owner );
for ( $i = 0; $i < Thessley_Module_Passkey_Login::REAUTH_MAX; $i++ ) {
	$call( $owner, $post( $dev3, $owner, array( 'password' => 'guess' . $i ) ) );
}
[ $code, $json ] = $call( $owner, $post( $dev3, $owner, array( 'password' => $password ) ) );
$ok( 'after 5 wrong guesses even the right password is paused (429)', 429 === $code && $active( $dev3 ) );
delete_transient( 'thessley_pk_reauth_' . $owner );
[ $code ] = $call( $owner, $post( $dev3, $owner, array( 'password' => $password ) ) );
$ok( 'and works again once the pause is over', 200 === $code && ! $active( $dev3 ) );

// --- cleanup ---------------------------------------------------------
foreach ( array( $owner, $other, $admin ) as $uid ) {
	delete_transient( 'thessley_pk_reauth_' . $uid );
	$wpdb->delete( Thessley_Passkey_Store::passkeys_table(), array( 'user_id' => $uid ) );
	wp_delete_user( $uid );
}
$left = (int) $wpdb->get_var( "SELECT COUNT(*) FROM " . Thessley_Passkey_Store::passkeys_table() . " WHERE label = 'zz-revoke-test'" );
$ok( 'cleaned up', 0 === $left );
echo $bad ? "FAILED: $bad\n" : "ALL PASS\n";
