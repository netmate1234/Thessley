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
 * the gate below if a check ever misfires.
 *
 * The helper functions below are always defined, even under WP_CLI or the
 * kill switch — regular plugin code (admin UI, cron) calls them too (e.g.
 * to manage the local blocklist), and those callers run in contexts this
 * file can't distinguish from a gated HTTP request at define-time.
 */

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

	/**
	 * Private/reserved IPv4 space (RFC 1918 + IANA special-purpose registry).
	 * Shared by every module: REMOTE_ADDR can't be spoofed over TCP, so a
	 * "bogon" source address only ever means a LAN/dev/VPN client or a
	 * reverse proxy passing an internal hop IP — never an attacker. Blocking
	 * on it has no security value and guarantees self-lockout, so nothing in
	 * this plugin (external lists, local escalation) is allowed to block it.
	 */
	function wpopsec_reserved_cidrs() {
		return array(
			'0.0.0.0/8',
			'10.0.0.0/8',
			'100.64.0.0/10',
			'127.0.0.0/8',
			'169.254.0.0/16',
			'172.16.0.0/12',
			'192.0.0.0/24',
			'192.0.2.0/24',
			'192.88.99.0/24',
			'192.168.0.0/16',
			'198.18.0.0/15',
			'198.51.100.0/24',
			'203.0.113.0/24',
			'224.0.0.0/4',
			'240.0.0.0/4',
		);
	}

	function wpopsec_cidr_to_range( $cidr ) {
		list( $ip, $prefix ) = explode( '/', $cidr );
		$mask  = ( 0xFFFFFFFF << ( 32 - (int) $prefix ) ) & 0xFFFFFFFF;
		$start = ip2long( $ip ) & $mask;
		return array( $start, $start | ( ~$mask & 0xFFFFFFFF ) );
	}

	/** @return array<int, array{0:int,1:int}> */
	function wpopsec_reserved_ranges() {
		static $ranges = null;
		if ( null === $ranges ) {
			$ranges = array_map( 'wpopsec_cidr_to_range', wpopsec_reserved_cidrs() );
		}
		return $ranges;
	}

	function wpopsec_ip_is_reserved( $ip ) {
		$long = is_int( $ip ) ? $ip : ip2long( $ip );
		if ( false === $long ) {
			return false;
		}
		foreach ( wpopsec_reserved_ranges() as $r ) {
			if ( $long >= $r[0] && $long <= $r[1] ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Optional operator-supplied trusted-networks file (CIDR per line, '#'
	 * comments) — e.g. known search-engine crawler ranges you never want
	 * blocked. Path is configurable per install (wpopsec_trusted_networks_file
	 * option), not hardcoded, so this stays a general plugin feature rather
	 * than something tied to one specific host's file layout.
	 */
	function wpopsec_trusted_ranges() {
		static $ranges = null;
		if ( null !== $ranges ) {
			return $ranges;
		}

		$ranges = array();
		$path   = get_option( 'wpopsec_trusted_networks_file', '' );
		if ( '' === $path || ! is_readable( $path ) ) {
			return $ranges;
		}

		foreach ( file( $path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) ?: array() as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] || false === strpos( $line, '/' ) ) {
				continue;
			}
			$ranges[] = wpopsec_cidr_to_range( $line );
		}

		return $ranges;
	}

	function wpopsec_ip_is_trusted( $ip ) {
		$long = is_int( $ip ) ? $ip : ip2long( $ip );
		if ( false === $long ) {
			return false;
		}
		foreach ( wpopsec_trusted_ranges() as $r ) {
			if ( $long >= $r[0] && $long <= $r[1] ) {
				return true;
			}
		}
		return false;
	}

	/** Combined "never enforce against this IP" check — reserved + operator-trusted. */
	function wpopsec_ip_is_exempt( $ip ) {
		return wpopsec_ip_is_reserved( $ip ) || wpopsec_ip_is_trusted( $ip );
	}

	/**
	 * Shared cross-module IP escalation: any check can call this to add an
	 * IP to a short-lived local blocklist that ip-blocklist also enforces,
	 * so one module's detection protects against that IP everywhere, not
	 * just for the request that triggered it.
	 */
	function wpopsec_local_blocklist_file() {
		return WPMU_PLUGIN_DIR . '/wp-opsec-checks/data/local-blocklist-ranges.php';
	}

	function wpopsec_local_blocklist_add( $ip, $reason, $ttl_seconds = DAY_IN_SECONDS ) {
		$long = ip2long( $ip );
		if ( false === $long || wpopsec_ip_is_exempt( $long ) ) {
			return false;
		}

		$list        = get_option( 'wpopsec_local_blocklist', array() );
		$list[ $ip ] = array(
			'reason'     => (string) $reason,
			'added_at'   => time(),
			'expires_at' => time() + (int) $ttl_seconds,
		);
		update_option( 'wpopsec_local_blocklist', $list, false );

		wpopsec_local_blocklist_rebuild();

		return true;
	}

	/** Drops expired entries and rewrites the compiled range file. */
	function wpopsec_local_blocklist_rebuild() {
		$list = get_option( 'wpopsec_local_blocklist', array() );
		$now  = time();
		$kept = array();

		foreach ( $list as $ip => $entry ) {
			if ( ! empty( $entry['expires_at'] ) && $entry['expires_at'] < $now ) {
				continue;
			}
			$kept[ $ip ] = $entry;
		}

		if ( count( $kept ) !== count( $list ) ) {
			update_option( 'wpopsec_local_blocklist', $kept, false );
		}

		$ranges = array();
		foreach ( array_keys( $kept ) as $ip ) {
			$long = ip2long( $ip );
			if ( false !== $long ) {
				$ranges[] = array( $long, $long );
			}
		}
		usort( $ranges, function ( $a, $b ) { return $a[0] <=> $b[0]; } );

		$file = wpopsec_local_blocklist_file();
		$dir  = dirname( $file );
		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$export = "<?php\n// Auto-generated by wp-opsec. Do not edit.\nreturn " . var_export( $ranges, true ) . ";\n";
		$tmp    = $file . '.tmp-' . bin2hex( random_bytes( 4 ) );
		file_put_contents( $tmp, $export, LOCK_EX );
		rename( $tmp, $file );

		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $file, true );
		}
	}
}

if ( defined( 'WPOPSEC_DISABLE' ) && WPOPSEC_DISABLE ) {
	return;
}

// CLI/cron has no real "visitor" and REMOTE_ADDR is unreliable there
// (often unset or a loopback placeholder) — never gate it, only HTTP requests.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	return;
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
