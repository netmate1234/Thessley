<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pulls known-bad IP ranges from public reputation lists and normalizes
 * them to a flat list of [start, end] IPv4 integer ranges.
 */
class WPOpsec_IP_Blocklist_Fetcher {

	const SOURCES = array(
		'cins'    => 'https://cinsscore.com/list/ci-badguys.txt',
		'dshield' => 'https://feeds.dshield.org/block.txt',
	);

	/**
	 * @return array<int, array{0:int,1:int,2:string}> ranges as [start, end, source]
	 */
	public static function fetch_all() {
		$ranges = array();

		foreach ( self::SOURCES as $source => $url ) {
			$body = self::download( $url );
			if ( false === $body ) {
				continue;
			}

			$parsed = 'cins' === $source
				? self::parse_ip_list( $body )
				: self::parse_range_list( $body );

			foreach ( $parsed as $range ) {
				$ranges[] = array( $range[0], $range[1], $source );
			}
		}

		return $ranges;
	}

	private static function download( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'    => 30,
				'user-agent' => 'wp-opsec/' . WPOPSEC_VERSION,
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		return wp_remote_retrieve_body( $response );
	}

	/** One bare IPv4 per line (CINS format). */
	private static function parse_ip_list( $body ) {
		$ranges = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			$long = ip2long( $line );
			if ( false !== $long ) {
				$ranges[] = array( $long, $long );
			}
		}

		return $ranges;
	}

	/** Whitespace-delimited "start end ..." per line (DShield format). */
	private static function parse_range_list( $body ) {
		$ranges = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}

			$fields = preg_split( '/\s+/', $line );
			if ( count( $fields ) < 2 ) {
				continue;
			}

			$start = ip2long( $fields[0] );
			$end   = ip2long( $fields[1] );
			if ( false !== $start && false !== $end && $end >= $start ) {
				$ranges[] = array( $start, $end );
			}
		}

		return $ranges;
	}
}
