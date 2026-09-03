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
			// php-cgi argument injection (CVE-2012-1823 / CVE-2024-4577): a
			// literal "-d" flag lets the caller set arbitrary php.ini
			// directives (allow_url_include, auto_prepend_file, etc.), and
			// %AD (soft hyphen) is the standard bypass for filters that
			// only block a literal "-". Matches the technique itself,
			// independent of which directive or wrapper follows it — a
			// payload using this without also tripping the php:// wrapper
			// signature above would otherwise pass through untouched.
			array( 'id' => 'cmdi_phpcgi_arg_injection', 'category' => 'cmdi', 'regex' => '/%(?:25)?ADd\b/i' ),

			// Misc
			array( 'id' => 'other_null_byte', 'category' => 'other', 'regex' => '/%00|\x00/' ),
			// CVE-2026-76581 (CVSS 9.8): unauthenticated admin takeover in
			// WPMU DEV Dashboard's Hub SSO. wdpsso_step1 signs an
			// unseparated token+state+redirect+domain blob; wdpsso_step2
			// verifies a shorter field list that omits domain, so moving
			// domain into redirect lets a forged signature pass. Real,
			// currently-active mass-scanning traffic (confirmed in this
			// site's own logs). Query-string category, not an always-on
			// path signature, since a site that legitimately runs this
			// plugin's SSO feature has real traffic here — sites that
			// don't run it lose nothing by blocking it either way.
			array( 'id' => 'other_wdpsso_hub_sso_cve202676581', 'category' => 'other', 'regex' => '/action=wdpsso_step[12]\b/i' ),
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

if ( ! function_exists( 'wpopsec_query_guard_path_patterns' ) ) {
	/**
	 * Matched against the URL path, not the query string — and always
	 * checked regardless of the category toggles above, unlike everything
	 * else in this file. A query-string pattern (e.g. an XSS event-handler
	 * regex) has some real, if small, false-positive surface against
	 * legitimate content, which is what the categories exist to let an
	 * admin tune. These don't: every path here is a known vulnerable or
	 * webshell-probe file with no legitimate reason to ever be requested
	 * on a real WordPress site, so there's nothing to weigh — a hit is a
	 * hit. A request with no query string at all previously skipped this
	 * whole check entirely, missing exactly this class of attack: e.g.
	 * PHPUnit's eval-stdin.php RCE probe (CVE-2017-9841) is a bare path
	 * with no query string, so it never reached any pattern here before.
	 */
	function wpopsec_query_guard_path_patterns() {
		return array(
			array( 'id' => 'path_phpunit_evalstdin', 'regex' => '#/eval-stdin\.php(?:$|[/?])#i' ),
			// .env.local / .env.production / etc are at least as common in
			// the wild as bare .env — a real gap in the first version of
			// this pattern, caught by checking real logged attack traffic
			// (/.env.development, /.env.local, /.env.production,
			// /.env.staging all sailed through untouched) rather than
			// assuming the narrower pattern was enough.
			array( 'id' => 'path_dotenv_exposed', 'regex' => '#(?:^|/)\.env(?:\.[a-z0-9_-]+)?(?:$|[/?])#i' ),
			array( 'id' => 'path_git_config_exposed', 'regex' => '#/\.git/config(?:$|[/?])#i' ),
			array( 'id' => 'path_wpconfig_backup', 'regex' => '#/wp-config\.php(?:\.bak|~|\.save|\.old|\.orig|\.swp)(?:$|[/?])#i' ),
			// The query-string traversal_dotdot signature above never
			// covers this: "../" in the *path* itself, not a query param —
			// seen in real logged traffic (/toolbox-resource/../serverconfig.xml).
			array( 'id' => 'path_traversal_dotdot', 'regex' => '#\.\.[/\\\\]#' ),
			// Whole-site backup archive probes — anchored to the root
			// (never wp-content/uploads/..., where a real uploaded file by
			// this exact name could legitimately live) since a bare
			// /backup.zip at the domain root has no legitimate WordPress
			// origin: uploads always live under a path, never site root.
			// Seen in real logged traffic hitting all of these stems.
			array( 'id' => 'path_backup_archive_probe', 'regex' => '#^/(?:backup|backups|www|wwwroot|htdocs|public_html|site|website)\.(?:zip|rar|7z|tar\.gz|tgz|sql|sql\.gz)(?:$|\?)#i' ),
		);
	}

	function wpopsec_query_guard_scan_path( $path ) {
		foreach ( wpopsec_query_guard_path_patterns() as $pattern ) {
			if ( preg_match( $pattern['regex'], $path ) ) {
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
		// Unlike most checks, this one previously had no exemption at all —
		// deliberately, since an attack signature is an attack signature
		// regardless of source. An explicit allowlist entry overrides that:
		// an admin who's said "never block this IP" means it, even here.
		// LAN/reserved/trusted-CIDR IPs remain covered too, just as a
		// side effect of using the same shared check every other module does.
		if ( wpopsec_ip_is_exempt( wpopsec_client_ip() ) ) {
			return null;
		}

		$uri  = (string) ( $_SERVER['REQUEST_URI'] ?? '' );
		$path = rawurldecode( strtok( $uri, '?' ) );
		$qs   = isset( $_SERVER['QUERY_STRING'] ) ? (string) $_SERVER['QUERY_STRING'] : '';

		// Path probes run first and unconditionally — a request with no
		// query string at all used to skip this whole check, missing
		// exactly the attacks that live in the path instead (see
		// wpopsec_query_guard_path_patterns()'s own docblock).
		$hit      = wpopsec_query_guard_scan_path( $path );
		$via_path = null !== $hit;

		if ( ! $hit && '' !== $qs ) {
			$categories = get_option( 'wpopsec_query_guard_categories', array( 'sqli', 'xss', 'traversal', 'cmdi', 'other' ) );
			$decoded    = rawurldecode( $qs );
			$hit        = wpopsec_query_guard_scan( $qs, $categories ) ?: wpopsec_query_guard_scan( $decoded, $categories );
		}

		if ( ! $hit ) {
			return null;
		}

		$mode    = get_option( 'wpopsec_query_guard_mode', 'log' );
		$snippet = $via_path
			? 'path: ' . substr( $path, 0, 200 )
			: 'qs: ' . substr( str_replace( array( "\r", "\n" ), ' ', rawurldecode( $qs ) ), 0, 200 );

		if ( 'block' !== $mode ) {
			wpopsec_log_event( 'query-guard', $hit['id'], 'logged', $snippet );
			return null;
		}

		wpopsec_log_event( 'query-guard', $hit['id'], 'blocked', $snippet );

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
	},
	// Priority 5: other checks (ip-blocklist, login-guard, rate-limiter,
	// user-enum...) sit at the default 10, and the early gate stops at the
	// first one that blocks. A request whose IP happens to also be on a
	// reputation list or from a blocked country would get wp_die()'d by
	// one of those before this signature scan ever ran — silently losing
	// the query-guard log entry even in log-only mode, not just the block.
	// Running the signature scan first means it always gets to log (or
	// act on) what it actually detected, independent of what else about
	// the request also happened to match.
	5
);
