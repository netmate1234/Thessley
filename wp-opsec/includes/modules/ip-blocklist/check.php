<?php
// Copied verbatim into wp-content/mu-plugins/wp-opsec-checks/ by the
// ip-blocklist module on activation. Runs inside wp-opsec-early.php.

wpopsec_register_check(
	function () {
		static $ranges = null;

		if ( null === $ranges ) {
			$data_file = __DIR__ . '/data/ip-blocklist-ranges.php';
			$ranges    = file_exists( $data_file ) ? require $data_file : array();
		}

		if ( empty( $ranges ) ) {
			return null;
		}

		$ip = wpopsec_client_ip();
		if ( '' === $ip || false === strpos( $ip, '.' ) ) {
			return null; // no IPv4 to check (IPv6 not covered by these sources)
		}

		$allowlist = get_option( 'wpopsec_ip_allowlist', array() );
		if ( in_array( $ip, (array) $allowlist, true ) ) {
			return null; // never block an explicitly trusted IP, e.g. your own
		}

		$needle = ip2long( $ip );
		if ( false === $needle ) {
			return null;
		}

		if ( ! wpopsec_ip_in_ranges( $needle, $ranges ) ) {
			return null;
		}

		$mode = get_option( 'wpopsec_ip_blocklist_mode', 'log' );

		if ( 'block' !== $mode ) {
			error_log( "wp-opsec ip-blocklist: would block {$ip} (log-only mode)" );
			return null;
		}

		return array( 'reason' => 'Access denied.' );
	}
);

if ( ! function_exists( 'wpopsec_ip_in_ranges' ) ) {
	/** @param array<int, array{0:int,1:int}> $ranges sorted, non-overlapping */
	function wpopsec_ip_in_ranges( $needle, array $ranges ) {
		$lo = 0;
		$hi = count( $ranges ) - 1;

		while ( $lo <= $hi ) {
			$mid   = (int) ( ( $lo + $hi ) / 2 );
			$range = $ranges[ $mid ];

			if ( $needle < $range[0] ) {
				$hi = $mid - 1;
			} elseif ( $needle > $range[1] ) {
				$lo = $mid + 1;
			} else {
				return true;
			}
		}

		return false;
	}
}
