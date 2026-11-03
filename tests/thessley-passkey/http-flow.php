<?php
/**
 * End-to-end HTTP checks for the standalone Thessley Passkey plugin.
 *
 *   php tests/thessley-passkey/http-flow.php http://127.0.0.1:8099
 *
 * Exercises the real wp-login.php page, the real REST endpoints (with
 * cookies), and the real profile screen — the same requests the browser and
 * the Android app make. Run tests/thessley-passkey/http-setup.php (wp eval-file) first.
 */

// Test scripts: run from WP-CLI or the command line, never from the web.
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) {
	exit;
}

$base = rtrim( $argv[1] ?? 'http://127.0.0.1:8099', '/' );
$info = json_decode( file_get_contents( '/tmp/opencode/pk-http.json' ), true );
if ( ! $info ) {
	fwrite( STDERR, "Run tests/thessley-passkey/http-setup.php first.\n" );
	exit( 2 );
}

$bad = 0;
function ok( $name, $cond, $extra = '' ) {
	global $bad;
	echo ( $cond ? 'PASS ' : 'FAIL ' ) . $name . ( $cond || '' === $extra ? '' : "  [$extra]" ) . "\n";
	if ( ! $cond ) {
		$bad++;
	}
}

function http( $method, $url, $body = null, $jar = null, $headers = array() ) {
	$ch = curl_init( $url );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_CUSTOMREQUEST  => $method,
			CURLOPT_FOLLOWLOCATION => false,
			CURLOPT_TIMEOUT        => 20,
			CURLOPT_HTTPHEADER     => array_merge( array( 'Accept: application/json, text/html' ), $headers ),
		)
	);
	if ( null !== $body ) {
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $body );
	}
	if ( $jar ) {
		curl_setopt( $ch, CURLOPT_COOKIEJAR, $jar );
		curl_setopt( $ch, CURLOPT_COOKIEFILE, $jar );
	}
	$raw  = curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
	$err  = curl_error( $ch );
	curl_close( $ch );

	return array( $code, $raw, $err );
}

function rest_url( $route ) {
	return $GLOBALS['base'] . '/?rest_route=' . rawurlencode( $route );
}

function sign_for( $type, $request_id, $nonce, $timestamp, $action ) {
	$msg = implode( '|', array( 'thessley_passkey_v1', $type, $request_id, $GLOBALS['info']['home'], $nonce, (string) $timestamp, $action ) );
	$key = openssl_pkey_get_private( $GLOBALS['info']['key_pem'] );
	openssl_sign( $msg, $sig, $key, OPENSSL_ALGO_SHA256 );

	return base64_encode( $sig );
}

$jar  = tempnam( sys_get_temp_dir(), 'pkjar' );
$jar2 = tempnam( sys_get_temp_dir(), 'pkjar' );

echo "== wp-login.php\n";
list( $code, $html ) = http( 'GET', $base . '/wp-login.php', null, $jar );
ok( 'login page returns 200', 200 === $code, (string) $code );
ok( 'passkey box is rendered', false !== strpos( $html, 'thessley-passkey-box' ) );
ok( 'QR container is rendered', false !== strpos( $html, 'thessley-passkey-qr' ) );
ok( 'QR library is enqueued', false !== strpos( $html, 'thessley-qr' ) );

echo "== start + approve + session\n";
list( $code, $json ) = http( 'POST', rest_url( '/thessley/v1/passkey/login/start' ), array(), $jar );
$start = json_decode( $json, true );
ok( 'login/start returns 200 JSON', 200 === $code && is_array( $start ), (string) $code . ' ' . substr( (string) $json, 0, 120 ) );
$id    = $start['request_id'];
$nonce = $start['nonce'];

list( $code, $json ) = http( 'GET', rest_url( "/thessley/v1/passkey/login/{$id}/status" ), null, $jar );
ok( 'status is pending before the phone answers', 200 === $code && 'pending' === json_decode( $json, true )['status'] );

$ts = time();
list( $code, $json ) = http(
	'POST',
	rest_url( "/thessley/v1/passkey/login/{$id}/respond" ),
	array(
		'credential_id' => $info['credential'],
		'action'        => 'approve',
		'timestamp'     => $ts,
		'signature'     => sign_for( 'login', $id, $nonce, $ts, 'approve' ),
	)
);
ok( 'phone approval accepted over HTTP', 200 === $code && 'ok' === json_decode( $json, true )['result'], (string) $code . ' ' . substr( (string) $json, 0, 120 ) );

list( $code, $json ) = http( 'GET', rest_url( "/thessley/v1/passkey/login/{$id}/status" ), null, $jar );
$status = json_decode( $json, true );
ok( 'approving browser is signed in', 200 === $code && 'approved' === $status['status'] && ! empty( $status['redirect_to'] ), (string) $json );

list( $code, $html ) = http( 'GET', $base . '/wp-admin/profile.php', null, $jar );
ok( 'session opens the profile page', 200 === $code && false !== strpos( $html, 'Thessley Passkey devices' ), (string) $code );

echo "== browser binding (login CSRF)\n";
list( $code, $json ) = http( 'POST', rest_url( '/thessley/v1/passkey/login/start' ), array(), $jar );
$start2 = json_decode( $json, true );
$ts2 = time();
list( $code, $json ) = http(
	'POST',
	rest_url( "/thessley/v1/passkey/login/{$start2['request_id']}/respond" ),
	array(
		'credential_id' => $info['credential'],
		'action'        => 'approve',
		'timestamp'     => $ts2,
		'signature'     => sign_for( 'login', $start2['request_id'], $start2['nonce'], $ts2, 'approve' ),
	)
);
ok( 'second approval accepted', 200 === $code );
list( $code, $json ) = http( 'GET', rest_url( "/thessley/v1/passkey/login/{$start2['request_id']}/status" ), null, $jar2 );
ok( 'a browser that never called start gets no session', 'pending' === json_decode( $json, true )['status'], (string) $json );

echo "== TPM challenge endpoint\n";
list( $code, $json ) = http( 'POST', rest_url( '/thessley/v1/passkey/enroll/nope/tpm-challenge' ), array( 'ek_certs' => array(), 'ak_public' => '' ) );
ok( 'unknown enrolment id is refused (409)', 409 === $code, (string) $code );

echo "== rate limiting\n";
$codes = array();
for ( $i = 0; $i < 21; $i++ ) {
	list( $code ) = http( 'POST', rest_url( '/thessley/v1/passkey/login/start' ), array(), $jar );
	$codes[] = $code;
}
ok( 'the 21st start from one IP is throttled (429)', 429 === end( $codes ), (string) end( $codes ) );

@unlink( $jar );
@unlink( $jar2 );

echo $bad ? "\n$bad FAILED\n" : "\nALL PASSED\n";
exit( $bad ? 1 : 0 );
