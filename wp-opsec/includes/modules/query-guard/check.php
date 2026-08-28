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
		$qs = isset( $_SERVER['QUERY_STRING'] ) ? (string) $_SERVER['QUERY_STRING'] : '';
		if ( '' === $qs ) {
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
			error_log( "wp-opsec query-guard: would block [{$hit['id']}] (log-only mode) qs=\"{$snippet}\"" );
			return null;
		}

		error_log( "wp-opsec query-guard: blocked [{$hit['id']}] qs=\"{$snippet}\"" );
		return array( 'reason' => 'Access denied.' );
	}
);
