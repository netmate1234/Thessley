<?php
/**
 * Behavioural checks for the standalone Thessley Passkey plugin.
 *
 *   wp --path=/tmp/opencode/wp/wordpress eval-file tests/standalone-checks.php
 *
 * Runs against a throwaway WordPress with ONLY this plugin active, which is
 * the point of the split: nothing here may depend on Thessley Security
 * Hardening. Every row, transient, option and user it creates is removed or
 * restored at the end, and outbound HTTP is short-circuited.
 */

add_filter( 'pre_http_request', function () { return new WP_Error( 'blocked', 'no outbound HTTP in tests' ); }, 10, 1 );

$bad = 0;
$ok  = function ( $name, $cond, $extra = '' ) use ( &$bad ) {
	echo ( $cond ? 'PASS ' : 'FAIL ' ) . $name . ( $cond || '' === $extra ? '' : "  [$extra]" ) . "\n";
	if ( ! $cond ) {
		$bad++;
	}
};

global $wpdb;
$requests_table = Thessley_Passkey_Store::requests_table();
$passkeys_table = Thessley_Passkey_Store::passkeys_table();

$_SERVER['REMOTE_ADDR'] = '198.51.100.7';

/* ---------- helpers ---------- */

function pk_test_keypair() {
	$key = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
	openssl_pkey_export( $key, $pem );
	$details = openssl_pkey_get_details( $key );
	$der     = base64_decode( preg_replace( '/-----[^-]+-----|\s+/', '', $details['key'] ) );

	return array(
		'pem'     => $pem,
		'public'  => base64_encode( $der ),
		'sign'    => function ( $message ) use ( $key ) {
			openssl_sign( $message, $sig, $key, OPENSSL_ALGO_SHA256 );
			return base64_encode( $sig );
		},
		'key'     => $key,
	);
}

function pk_test_approve( $request_id, $nonce, $keypair, $action = 'approve', $type = 'login' ) {
	$ts  = time();
	$msg = Thessley_Passkey_Crypto::canonical_string( $type, $request_id, home_url(), $nonce, $ts, $action );

	return array(
		'credential_id' => $GLOBALS['pk_credential'],
		'action'        => $action,
		'timestamp'     => $ts,
		'signature'     => $keypair['sign']( $msg ),
	);
}

function pk_test_rest( $method, $route, $params = array(), $headers = array() ) {
	$request = new WP_REST_Request( $method, $route );
	foreach ( $params as $k => $v ) {
		$request->set_param( $k, $v );
	}
	foreach ( $headers as $k => $v ) {
		$request->add_header( $k, $v );
	}
	return rest_do_request( $request );
}

/* ---------- bootstrap ---------- */

echo "== bootstrap\n";
$ok( 'both tables exist', 2 === count( $wpdb->get_col( "SHOW TABLES LIKE '%thessley_passkey%'" ) ) );
$ok( 'prune cron is scheduled', false !== wp_next_scheduled( Thessley_Passkey_Login::CRON_HOOK ) );
$ok( 'activation version stored', (int) get_option( 'thessley_passkey_db_version' ) === Thessley_Passkey_Store::DB_VERSION );
$ok( 'wp-login hooks registered', false !== has_action( 'login_footer', array( 'Thessley_Passkey_Login', 'login_form_markup' ) ) );
$ok( 'REST routes registered', isset( rest_get_server()->get_routes()['/thessley/v1/passkey/login/start'] ) );
$ok( 'admin menu entry registered', false !== has_action( 'admin_menu' ) );

echo "== store\n";
$alice = wp_insert_user( array( 'user_login' => 'pk_test_alice', 'user_pass' => wp_generate_password(), 'user_email' => 'pk_alice@example.test', 'role' => 'subscriber' ) );
$bob   = wp_insert_user( array( 'user_login' => 'pk_test_bob', 'user_pass' => wp_generate_password(), 'user_email' => 'pk_bob@example.test', 'role' => 'subscriber' ) );
$ok( 'test users created', $alice && $bob && ! is_wp_error( $alice ) && ! is_wp_error( $bob ) );

$alice_key = pk_test_keypair();
$bob_key   = pk_test_keypair();
$alice_cred = Thessley_Passkey_Store::add_passkey( $alice, $alice_key['public'], 'ES256', 'Alice phone' );
$bob_cred   = Thessley_Passkey_Store::add_passkey( $bob, $bob_key['public'], 'ES256', 'Bob phone' );
$ok( 'device enrolled (credential id 43 chars)', 43 === strlen( $alice_cred ), strlen( $alice_cred ) );
$devices = Thessley_Passkey_Store::devices_for_user( $alice );
$ok( 'device listed for its owner', 1 === count( $devices ) && 'Alice phone' === $devices[0]->label );
$ok( 'device not listed for another user', 1 === count( Thessley_Passkey_Store::devices_for_user( $bob ) ) && $bob_cred !== $alice_cred );

echo "== settings\n";
$ok( 'default mode is optional', 'optional' === Thessley_Passkey_Login::mode() );
update_option( 'thessley_passkey_mode', 'required' );
$ok( 'mode switch is read back', 'required' === Thessley_Passkey_Login::mode() );
update_option( 'thessley_passkey_identify', 1 );
$ok( 'username prompt switch is read back', true === Thessley_Passkey_Login::identify() );
ob_start();
Thessley_Passkey_Login::render_page();
$page = ob_get_clean();
$ok( 'settings page renders the form', false !== strpos( $page, 'thessley_pk_save_settings' ) && false !== strpos( $page, 'Login method' ) );
$ok( 'settings page carries a nonce', false !== strpos( $page, '_wpnonce' ) );
update_option( 'thessley_passkey_mode', 'optional' );
update_option( 'thessley_passkey_identify', 0 );

echo "== anonymous login (mode optional, no username prompt)\n";
$start = pk_test_rest( 'POST', '/thessley/v1/passkey/login/start' );
$body  = $start->get_data();
$ok( 'start returns 200', 200 === $start->get_status(), (string) $start->get_status() );
$ok( 'start returns a request id and nonce', ! empty( $body['request_id'] ) && ! empty( $body['nonce'] ) );
$ok( 'app link names this site', false !== strpos( $body['app_link'], rawurlencode( home_url() ) ) || false !== strpos( $body['app_link'], home_url() ) );
$ok( 'no device reported for an anonymous request', false === $body['has_device'] );
$id    = $body['request_id'];
$nonce = $body['nonce'];
$GLOBALS['pk_credential'] = $alice_cred;

$status = pk_test_rest( 'GET', "/thessley/v1/passkey/login/{$id}/status" );
$ok( 'status is pending before approval', 'pending' === $status->get_data()['status'] );

$respond = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", pk_test_approve( $id, $nonce, $alice_key ) );
$ok( 'signed approval accepted', 200 === $respond->get_status() && 'ok' === $respond->get_data()['result'], wp_json_encode( $respond->get_data() ) );

$_COOKIE['thessley_pk_bt'] = 'not-the-bound-token';
$csrf = pk_test_rest( 'GET', "/thessley/v1/passkey/login/{$id}/status" );
$ok( 'approval is not delivered to an unbound browser', 'pending' === $csrf->get_data()['status'] );

$_COOKIE['thessley_pk_bt'] = get_transient( 'thessley_pk_bt_' . $id );
$done = pk_test_rest( 'GET', "/thessley/v1/passkey/login/{$id}/status" );
$ok( 'bound browser gets the approved session', 'approved' === $done->get_data()['status'] && ! empty( $done->get_data()['redirect_to'] ), wp_json_encode( $done->get_data() ) );
$ok( 'request row consumed after delivery', 'consumed' === Thessley_Passkey_Store::get_request( $id )->status );
$again = pk_test_rest( 'GET', "/thessley/v1/passkey/login/{$id}/status" );
$ok( 'replayed status is expired', 'expired' === $again->get_data()['status'] );

echo "== rejected responses\n";
$start = pk_test_rest( 'POST', '/thessley/v1/passkey/login/start' );
$b     = $start->get_data();
$id    = $b['request_id'];

$bad_sig = pk_test_approve( $id, $b['nonce'], $alice_key );
$bad_sig['signature'] = base64_encode( random_bytes( 70 ) );
$r = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", $bad_sig );
$ok( 'garbage signature rejected (401)', 401 === $r->get_status(), (string) $r->get_status() );

$stale = pk_test_approve( $id, $b['nonce'], $alice_key );
$stale['timestamp'] = time() - 600;
$r = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", $stale );
$ok( 'stale timestamp rejected (401)', 401 === $r->get_status(), (string) $r->get_status() );

$unknown = pk_test_approve( $id, $b['nonce'], $alice_key );
$unknown['credential_id'] = 'does-not-exist';
$r = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", $unknown );
$ok( 'unknown device rejected (401)', 401 === $r->get_status(), (string) $r->get_status() );

$good = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", pk_test_approve( $id, $b['nonce'], $alice_key ) );
$ok( 'still pending request can then be approved', 200 === $good->get_status() );
$replay = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", pk_test_approve( $id, $b['nonce'], $alice_key ) );
$ok( 'a resolved request cannot be approved twice (409)', 409 === $replay->get_status(), (string) $replay->get_status() );
Thessley_Passkey_Store::consume_request( $id );

echo "== account binding (username prompt)\n";
update_option( 'thessley_passkey_identify', 1 );
$start = pk_test_rest( 'POST', '/thessley/v1/passkey/login/start', array( 'username' => 'pk_test_alice' ) );
$b     = $start->get_data();
$ok( 'start for a known account reports its device', true === $b['has_device'] );
$id = $b['request_id'];

$GLOBALS['pk_credential'] = $bob_cred;
$r = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", pk_test_approve( $id, $b['nonce'], $bob_key ) );
$ok( "another account's device is refused (403)", 403 === $r->get_status(), (string) $r->get_status() );

$GLOBALS['pk_credential'] = $alice_cred;
$r = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", pk_test_approve( $id, $b['nonce'], $alice_key ) );
$ok( "the account's own device is accepted", 200 === $r->get_status() );
Thessley_Passkey_Store::consume_request( $id );

$start = pk_test_rest( 'POST', '/thessley/v1/passkey/login/start', array( 'username' => 'no-such-user-here' ) );
$b     = $start->get_data();
$ok( 'an unknown username looks like a real account without a device', 200 === $start->get_status() && false === $b['has_device'] );
$id = $b['request_id'];
$r  = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", pk_test_approve( $id, $b['nonce'], $alice_key ) );
$ok( 'no device can approve an unknown username (403)', 403 === $r->get_status(), (string) $r->get_status() );
Thessley_Passkey_Store::consume_request( $id );
update_option( 'thessley_passkey_identify', 0 );

echo "== 2fa enforcement\n";
update_option( 'thessley_passkey_mode', '2fa' );
$start = pk_test_rest( 'POST', '/thessley/v1/passkey/login/start' );
$b     = $start->get_data();
$id    = $b['request_id'];
$r     = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$id}/respond", pk_test_approve( $id, $b['nonce'], $alice_key ) );
$ok( 'app-only approval cannot finish a 2fa login (403)', 403 === $r->get_status(), (string) $r->get_status() );
Thessley_Passkey_Store::consume_request( $id );
update_option( 'thessley_passkey_mode', 'optional' );

echo "== enrolment\n";
wp_set_current_user( $alice );
$start = pk_test_rest( 'POST', '/thessley/v1/passkey/enroll/start' );
$b     = $start->get_data();
$ok( 'enroll start returns a request', 200 === $start->get_status() && ! empty( $b['request_id'] ) );
$new_key = pk_test_keypair();
$ts  = time();
$msg = Thessley_Passkey_Crypto::canonical_string( 'enroll', $b['request_id'], home_url(), $b['nonce'], $ts, 'register' );
$r = pk_test_rest(
	'POST',
	"/thessley/v1/passkey/enroll/{$b['request_id']}/respond",
	array(
		'public_key'  => $new_key['public'],
		'algorithm'   => 'ES256',
		'label'       => 'Second phone',
		'timestamp'   => $ts,
		'proof_signature' => $new_key['sign']( $msg ),
	)
);
$enrolled = $r->get_data();
$ok( 'enrolment accepted', 200 === $r->get_status() && 'ok' === $enrolled['result'], wp_json_encode( $enrolled ) );
$ok( 'enrolment returns the credential id', ! empty( $enrolled['credential_id'] ) );
$ok( 'enrolment names the account', 'pk_test_alice' === $enrolled['username'] );
$ok( 'no attestation chain means unverified', 'unverified' === $enrolled['attestation_status'] );
$labels = wp_list_pluck( Thessley_Passkey_Store::devices_for_user( $alice ), 'label' );
$ok( 'new device appears in the device list', in_array( 'Second phone', $labels, true ) );
$status = pk_test_rest( 'GET', "/thessley/v1/passkey/enroll/{$b['request_id']}/status" );
$ok( 'enroll status is approved', 'approved' === $status->get_data()['status'] );

echo "== rate limiting\n";
$coded = array();
for ( $i = 0; $i < 21; $i++ ) {
	$coded[] = pk_test_rest( 'POST', '/thessley/v1/passkey/login/start' )->get_status();
}
$ok( 'the 21st start in a window is throttled (429)', 429 === end( $coded ), (string) end( $coded ) );
foreach ( array( 'login_start', 'enroll_tpm', 'enroll_respond' ) as $bucket ) {
	delete_transient( 'thessley_pk_rl_' . $bucket . '_' . md5( '198.51.100.7' ) );
}

echo "== revocation and pruning\n";
$row = Thessley_Passkey_Store::get_passkey_row_id( $alice_cred );
$ok( 'revoke succeeds for the owner', Thessley_Passkey_Store::revoke( $row, $alice ) );
$ok( 'revoked device disappears from the list', ! in_array( $alice_cred, wp_list_pluck( Thessley_Passkey_Store::devices_for_user( $alice ), 'credential_id' ), true ) );
$start = pk_test_rest( 'POST', '/thessley/v1/passkey/login/start' );
$b     = $start->get_data();
$r     = pk_test_rest( 'POST', "/thessley/v1/passkey/login/{$b['request_id']}/respond", pk_test_approve( $b['request_id'], $b['nonce'], $alice_key ) );
$ok( 'revoked device cannot sign in (401)', 401 === $r->get_status(), (string) $r->get_status() );
Thessley_Passkey_Store::consume_request( $b['request_id'] );

$expired = Thessley_Passkey_Store::random_token();
$wpdb->insert( $requests_table, array( 'request_id' => $expired, 'type' => 'login', 'nonce' => 'n', 'status' => 'pending', 'requester_user_id' => 0, 'ip' => '127.0.0.1', 'created_at' => gmdate( 'Y-m-d H:i:s', time() - 7200 ), 'expires_at' => gmdate( 'Y-m-d H:i:s', time() - 3600 ) ) );
Thessley_Passkey_Store::prune_expired_requests();
$ok( 'expired requests are pruned', null === Thessley_Passkey_Store::get_request( $expired ) );

echo "== profile device list\n";
wp_set_current_user( $alice );
$m  = new ReflectionMethod( 'Thessley_Passkey_Login', 'render_devices_list_html' );
$m->setAccessible( true );
$m2 = new ReflectionMethod( 'Thessley_Passkey_Login', 'devices_list_allowed_html' );
$m2->setAccessible( true );
$raw  = $m->invoke( null, get_userdata( $alice ) );
$kses = wp_kses( $raw, $m2->invoke( null ) );
$norm = function ( $h ) { return preg_replace( '/\s+/', ' ', trim( $h ) ); };
$ok( 'device list shows the remaining device', false !== strpos( $kses, 'Second phone' ) );
$ok( 'allow-list keeps every legitimate attribute', $norm( $raw ) === $norm( $kses ) );
$ok( 'revoke button keeps its data attributes', false !== strpos( $kses, 'data-id=' ) && false !== strpos( $kses, 'data-nonce=' ) );

echo "== deactivate / reactivate\n";
Thessley_Passkey_Login::deactivate();
$ok( 'deactivation clears the prune cron', false === wp_next_scheduled( Thessley_Passkey_Login::CRON_HOOK ) );
$ok( 'deactivation keeps the tables', 2 === count( $wpdb->get_col( "SHOW TABLES LIKE '%thessley_passkey%'" ) ) );
Thessley_Passkey_Login::activate();
$ok( 'reactivation restores the cron', false !== wp_next_scheduled( Thessley_Passkey_Login::CRON_HOOK ) );

/* ---------- cleanup ---------- */
$wpdb->query( "DELETE FROM $passkeys_table WHERE user_id IN ($alice, $bob)" );
$wpdb->query( "DELETE FROM $requests_table WHERE requester_user_id IN ($alice, $bob)" );
foreach ( array( $alice, $bob ) as $uid ) {
	require_once ABSPATH . 'wp-admin/includes/user.php';
	wp_delete_user( $uid );
}
update_option( 'thessley_passkey_mode', 'optional' );
update_option( 'thessley_passkey_identify', 0 );
wp_set_current_user( 0 );

echo $bad ? "\n$bad FAILED\n" : "\nALL PASSED\n";
if ( $bad && defined( 'WP_CLI' ) ) {
	WP_CLI::halt( 1 );
}
