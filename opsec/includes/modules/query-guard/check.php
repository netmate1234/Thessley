<?php
// Copied verbatim into wp-content/mu-plugins/wp-opsec-checks/ by the
// query-guard module on activation. Runs inside wp-opsec-early.php.
//
// Scoped to the GET query string only, never POST bodies — POST carries
// legitimate rich content (block editor HTML, REST payloads) that would
// false-positive constantly against XSS-style patterns. A malicious
// pattern in a GET param is essentially never something a real visitor
// needs, which is also how opportunistic scanner/bot traffic actually
// probes sites (known exploit query strings blasted at random hosts).

if ( ! function_exists( 'wpopsec_query_guard_patterns' ) ) {
	function wpopsec_query_guard_patterns() {
		return array(
			// SQL injection
			array( 'id' => 'sqli_union_select', 'category' => 'sqli', 'regex' => '/\bunion\b(\s+all)?\s+select\b/i' ),
			array( 'id' => 'sqli_or_equals', 'category' => 'sqli', 'regex' => '/\bor\b\s*[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?/i' ),
			array( 'id' => 'sqli_sleep_benchmark', 'category' => 'sqli', 'regex' => '/\b(sleep|benchmark)\s*\(/i' ),
			array( 'id' => 'sqli_information_schema', 'category' => 'sqli', 'regex' => '/\binformation_schema\b/i' ),
			array( 'id' => 'sqli_extractvalue', 'category' => 'sqli', 'regex' => '/\b(extractvalue|updatexml)\s*\(/i' ),
			array( 'id' => 'sqli_comment_injection', 'category' => 'sqli', 'regex' => '/\'\s*(--|#|\/\*)/' ),

			// Cross-site scripting
			array( 'id' => 'xss_script_tag', 'category' => 'xss', 'regex' => '/<script[\s>\/]/i' ),
			array( 'id' => 'xss_js_protocol', 'category' => 'xss', 'regex' => '/javascript\s*:/i' ),
			array( 'id' => 'xss_event_handler', 'category' => 'xss', 'regex' => '/\bon(error|load|mouseover|focus|click)\s*=/i' ),
			array( 'id' => 'xss_svg_onload', 'category' => 'xss', 'regex' => '/<svg[^>]*onload/i' ),

			// Path traversal / local & remote file inclusion
			array( 'id' => 'traversal_dotdot', 'category' => 'traversal', 'regex' => '#\.\.[/\\\\]#' ),
			array( 'id' => 'traversal_etc_passwd', 'category' => 'traversal', 'regex' => '#etc/passwd#i' ),
			array( 'id' => 'traversal_php_wrapper', 'category' => 'traversal', 'regex' => '#php://(filter|input|memory)#i' ),
			array( 'id' => 'traversal_remote_wrapper', 'category' => 'traversal', 'regex' => '#\b(expect|data)://#i' ),

			// Command injection / webshell probes
			array( 'id' => 'cmdi_shell_functions', 'category' => 'cmdi', 'regex' => '/\b(system|exec|passthru|shell_exec|proc_open|popen)\s*\(/i' ),
			array( 'id' => 'cmdi_command_chain', 'category' => 'cmdi', 'regex' => '/;\s*(cat|ls|whoami|id|uname|wget|curl|nc)\b/i' ),
			array( 'id' => 'cmdi_backtick_exec', 'category' => 'cmdi', 'regex' => '/`[^`\n]{1,80}`/' ),
			array( 'id' => 'cmdi_base64_payload', 'category' => 'cmdi', 'regex' => '/base64_decode\s*\(/i' ),

			// Misc
			array( 'id' => 'other_null_byte', 'category' => 'other', 'regex' => '/%00|\x00/' ),
		);
	}

	function wpopsec_query_guard_scan( $haystack, array $enabled_categories ) {
		foreach ( wpopsec_query_guard_patterns() as $pattern ) {
			if ( ! in_array( $pattern['category'], $enabled_categories, true ) ) {
				continue;
			}
			if ( preg_match( $pattern['regex'], $haystack ) ) {
				return $pattern;
			}
		}
		return null;
	}
}

wpopsec_register_check(
	function () {
		if ( ! get_option( 'wpopsec_query_guard_block_xmlrpc', false ) ) {
			return null;
		}

		// Match the path itself, not basename(): Apache passes /xmlrpc.php/foo
		// straight to xmlrpc.php as PATH_INFO, and //xmlrpc.php reaches it too,
		// but basename() returns "foo" and "" for those — so a basename check
		// is bypassed by appending any segment to the URL.
		//
		// parse_url() is avoided deliberately: a leading "//" makes it read the
		// URI as protocol-relative, so "//xmlrpc.php" parses as a *host* with
		// no path and the check would be skipped entirely.
		$uri  = (string) ( $_SERVER['REQUEST_URI'] ?? '' );
		$path = rawurldecode( strtok( $uri, '?' ) );
		$path = preg_replace( '#/+#', '/', $path ); // collapse // and ///
		if ( ! preg_match( '#(?:^|/)xmlrpc\.php(?:/|$)#i', (string) $path ) ) {
			return null;
		}

		$ip_long = ip2long( wpopsec_client_ip() );

		// Jetpack is the one common legitimate xmlrpc.php consumer — allow
		// its published IPs through by default. Any other provider (backup
		// tools, remote publishers, etc.) goes through the general trusted-
		// networks file rather than us guessing at more hardcoded IP data.
		if ( false !== $ip_long ) {
			// wpopsec_ip_is_exempt() covers trusted-CIDR (what this checked
			// before), plus reserved space and the explicit allowlist —
			// strictly wider, never narrower, than the previous check.
			if ( wpopsec_ip_is_exempt( $ip_long ) ) {
				return null;
			}
			if ( get_option( 'wpopsec_qg_allow_jetpack', true ) ) {
				foreach ( get_option( 'wpopsec_qg_xmlrpc_allow_ranges', array() ) as $r ) {
					if ( $ip_long >= $r[0] && $ip_long <= $r[1] ) {
						return null;
					}
				}
			}
		}

		$mode = get_option( 'wpopsec_query_guard_mode', 'log' );

		if ( 'block' !== $mode ) {
			wpopsec_log_event( 'query-guard', 'xmlrpc_access', 'logged', 'log-only mode' );
			return null;
		}

		wpopsec_log_event( 'query-guard', 'xmlrpc_access', 'blocked' );

		$ip = wpopsec_client_ip();
		if ( '' !== $ip ) {
			// If the admin turned this on at all, they've said the site never
			// legitimately uses xmlrpc.php — any hit is worth escalating.
			wpopsec_local_blocklist_add( $ip, 'query-guard: xmlrpc_access' );
		}

		// Not wp_die() here deliberately: xmlrpc.php defines XMLRPC_REQUEST
		// before this runs, and WP's wp_die() detects that constant and
		// routes to its XML-RPC-aware die handler, which per XML-RPC
		// convention returns HTTP 200 with the error as a <fault> in the
		// body — the endpoint would still be neutralized, but "blocked"
		// should mean an actual 403 here, so set it directly and stop.
		status_header( 403 );
		nocache_headers();
		exit;
	}
);

wpopsec_register_check(
	function () {
		$qs = isset( $_SERVER['QUERY_STRING'] ) ? (string) $_SERVER['QUERY_STRING'] : '';
		if ( '' === $qs ) {
			return null;
		}

		// Unlike most checks, this one previously had no exemption at all —
		// deliberately, since an attack signature is an attack signature
		// regardless of source. An explicit allowlist entry overrides that:
		// an admin who's said "never block this IP" means it, even here.
		// LAN/reserved/trusted-CIDR IPs remain covered too, just as a
		// side effect of using the same shared check every other module does.
		if ( wpopsec_ip_is_exempt( wpopsec_client_ip() ) ) {
			return null;
		}

		$categories = get_option( 'wpopsec_query_guard_categories', array( 'sqli', 'xss', 'traversal', 'cmdi', 'other' ) );

		$decoded = rawurldecode( $qs );
		$hit     = wpopsec_query_guard_scan( $qs, $categories ) ?: wpopsec_query_guard_scan( $decoded, $categories );

		if ( ! $hit ) {
			return null;
		}

		$mode    = get_option( 'wpopsec_query_guard_mode', 'log' );
		$snippet = substr( str_replace( array( "\r", "\n" ), ' ', $decoded ), 0, 200 );

		if ( 'block' !== $mode ) {
			wpopsec_log_event( 'query-guard', $hit['id'], 'logged', "qs: {$snippet}" );
			return null;
		}

		wpopsec_log_event( 'query-guard', $hit['id'], 'blocked', "qs: {$snippet}" );

		$ip = wpopsec_client_ip();
		if ( '' !== $ip ) {
			// Escalate to the shared local blocklist so ip-blocklist catches
			// this IP on future requests too, not just this one. Gated on
			// query-guard's own mode being "block" (not just detecting a hit)
			// so an unverified/tuning-stage signature can't cause real blocks
			// via a side channel while its own module is still in log-only mode.
			wpopsec_local_blocklist_add( $ip, "query-guard: {$hit['id']}" );
		}

		return array( 'reason' => 'Access denied.' );
	}
);
