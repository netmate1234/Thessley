=== Opsec ===
Contributors: martinlundstrom
Tags: security, firewall, malware, geo-blocking, brute-force
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Modular WordPress security hardening — IP/country blocking, request inspection, file integrity, malware scanning, and real-time alerting.

== Description ==

Opsec is a modular security plugin. Each feature is a self-contained module you can enable, configure, and put into log-only or enforcing mode independently — nothing is all-or-nothing.

**Perimeter**

* **IP Blocklist** — blocks traffic from public IP-reputation feeds (CINS, DShield, Spamhaus DROP, FireHOL), merged and compiled into a single range list, plus a local list other modules can escalate into.
* **Geo Blocker** — blocks or allows traffic by country, using a compiled IP-to-country dataset (DB-IP Country Lite) checked before WordPress finishes loading.
* **Geo Login** — restricts wp-login.php specifically to an allow-list of countries, independent of the site-wide Geo Blocker.
* **Rate Limiter** — throttles requests per IP site-wide, escalating sustained floods into the shared local blocklist.

**Request inspection**

* **Query Guard** — inspects query strings and request bodies for SQL injection, XSS, path traversal, command injection, and obfuscated-payload signatures.
* **Login Guard** — rate-limits failed logins per IP, with a configurable lockout window.

**Detection**

* **File Integrity** — verifies core files against WordPress.org's published checksums, and plugins/themes against a local baseline you take yourself.
* **Malware Scanner** — scans plugin, theme, and upload files for webshell markers, obfuscated eval/assert chains, and injected-spam patterns.
* **Vulnerability Scan** — flags outdated, removed, and unmaintained plugins/themes.
* **User Watchdog** — watches privileged accounts for the changes a backdoor actually makes: new admin accounts, role escalation, hidden users.

**Hardening**

* **Security Headers** — standard hardening response headers, including opt-in HSTS for sites behind a TLS-terminating proxy.
* **User Enumeration** — blocks anonymous username harvesting via author-scan URLs and the REST users endpoint.
* **Hardening** — disables the file editor, blocks PHP execution in uploads, and flags hidden/disguised plugins.

**Overview**

* **Event Log** — a filterable, searchable record of everything every module has seen, with a 1–20 severity score per event.
* **Event Map** — blocked/logged events tinted on a world map by country.
* **Activity Log** — the mundane admin audit trail: who published, deleted, installed, or changed what.

**Ops**

* **Auto Updates** — per-plugin auto-update control, including a "flagged only" mode driven by the Vulnerability Scan's findings.
* **Alerts** — a real-time Telegram message and/or email when an event crosses a severity threshold you set, independently per channel.

= External services this plugin can connect to =

Each of these is either a standard security data feed or something you explicitly opt into — nothing is contacted without the relevant module being active:

* CINS Army, DShield, Spamhaus DROP, FireHOL (IP reputation feeds — IP Blocklist module)
* DB-IP.com Country Lite dataset, CC BY 4.0 (Geo Blocker / Geo Login modules)
* api.wordpress.org (core checksum verification — File Integrity module)
* Jetpack's published IP list (xmlrpc.php allowlist — Query Guard module)
* Telegram Bot API — only if you enable and configure Telegram alerts yourself

= Bundled third-party assets =

* World map outline used by the Event Map module: [flekschas/simple-world-map](https://github.com/flekschas/simple-world-map), CC BY-SA 3.0.

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/opsec`, or install directly through the WordPress plugins screen.
2. Activate the plugin.
3. Each module starts in log-only mode where applicable — review the Event Log for a few days before switching any module to Block.

== Frequently Asked Questions ==

= Will this lock me out of my own site? =

Every blocking module exempts your LAN, reserved/private IP space, and anything in the trusted-networks list, before it ever looks at the rest of its rules. Geo Blocker and Geo Login specifically cannot lock out your own network regardless of which countries you select.

= Does this slow down every page load? =

The early-request checks (IP Blocklist, Geo Blocker, Geo Login, Rate Limiter, Query Guard's query-string scan) run as a must-use plugin before WordPress finishes bootstrapping, using compiled binary-search lookups rather than database queries — no per-request network calls, no per-request external API hits.

= Where does the geo data come from? =

DB-IP's free Country Lite database (CC BY 4.0), refreshed automatically on a schedule.

== Changelog ==

= 1.0.3 =
* Silenced Plugin Check's remaining 19 false-positive errors (verified safe table-name/query-template SQL patterns, and server-side threat-feed URLs misidentified as front-end assets) with justified inline annotations, rather than rewriting already-safe code.

= 1.0.2 =
* Removed a debug error_log() call that fired on every logged security event, duplicating the Event Log's own database record on every request.
* Scoped the early-gate's check-dispatch variables out of the global PHP namespace.

= 1.0.1 =
* Verified against the official Plugin Check tool: added missing direct-file-access guards on 6 files, replaced date() with gmdate() at 3 sites, escaped two output sites (Event Map's SVG, paginate_links() calls), and moved 20 file writes/renames/deletes to the WP_Filesystem API.

= 1.0.0 =
* First release prepared for the WordPress.org plugin directory.
* Fixed a text-domain mismatch (translation strings used 'wp-opsec', the plugin header declares 'opsec').
* Documented the bundled world-map graphic's license (CC BY-SA 3.0) alongside the existing external-services disclosures.

= 0.1.9 =
* New Import/Export tab (Other): back up or restore every module's settings as a single JSON file, with each module optionally left out on either side. API keys/tokens are included by default, with an option to leave them out.
* Query Guard's CVE-2026-63030/CVE-2026-60137 ("wp2shell") signature now also catches the pretty-permalink form of the REST batch endpoint, not just the query-string form — closes a gap confirmed live on a client site.
* User Enumeration's per-plugin REST route list replaced with a general pattern, after real traffic showed a scanner fuzzing dozens of plugin namespaces the list didn't cover.

= 0.1.8 =
* New Query Guard signature for CVE-2026-63030/CVE-2026-60137 ("wp2shell"), the unauthenticated pre-auth RCE chain in WordPress core's REST batch endpoint (CISA KEV, 2026-07-21).
* Admin menu: "Overview" cluster renamed to "Logs", "Ops" cluster renamed to "Other".

= 0.1.7 =
* New Bot Log tab (Overview): a separate record of verified good-bot visits, distinct from the Event Log.
* IP Blocklist Event Log and unwantedip reports now name the actual matched source feed instead of a generic label.
* unwantedip.eagleeye-intelligence.com added as a sixth IP Blocklist source (WordPress-targeting IPs, requires the same API key as IP Sharing).
* Trusted-networks canonical source moved to wp-opsec.eagleeye-intelligence.com, with automatic weekly updates from Google, Bing, DuckDuckGo, OpenAI, and Cloudflare's own published IP ranges.
* Query Guard: new always-on path-probe detection (PHPUnit RCE, exposed .env/.git, wp-config backups, backup-archive probes, path traversal), a signature for CVE-2026-76581 (WPMU DEV Dashboard Hub SSO), and its checks now run early enough to be logged even when another module blocks the same request first.
* User Enumeration: new setting to hide WordPress's built-in user sitemap, and blocking extended to WooCommerce, LearnDash, Tutor LMS, Ultimate Member, bbPress, MemberPress, and BuddyPress's own user/customer-listing REST routes.
* Fixed a real opcache-staleness bug across every module's check.php deployment that could serve stale logic to a live request after an update.

= 0.1.6 =
* New Query Guard signature for the php-cgi %ADd argument-injection technique (CVE-2012-1823 / CVE-2024-4577).
* Query Guard's signature scan now runs ahead of the default-priority checks, so its detections get logged even when another module (IP Blocklist, Login Guard, etc.) ultimately blocks the same request first.

= 0.1.5 =
* New IP Blocklist source: unwantedip.eagleeye-intelligence.com's WordPress-targeting IP feed (requires the same API key as IP Sharing).
* IP Blocklist Event Log entries now name the actual source feed(s) that matched, instead of a generic "reputation list".
* Geo Login now runs before Geo Blocker on wp-login.php requests, so its own block (and local-blocklist escalation) is no longer pre-empted by the site-wide check.

= 0.1.4 =
* Telegram Alerts renamed to Alerts, with email added as a second, independently-configured notification channel alongside Telegram.
* Fixed email alerts silently bouncing when the subject line contained non-ASCII characters.
* Dashboard now shows a "not fully protected yet" checklist for core baseline modules, separate from optional integrations.
* WPScan API token field now shows in clear text instead of masked.

= 0.1.3 =
* IP Sharing's API key field now shows in clear text instead of masked, so it can be checked or copied at a glance.

= 0.1.2 =
* New Whitelist tab: individually-listed IPs and the trusted-networks CIDR feed both moved here from IP Blocklist, now exempt from every blocking module (IP Blocklist, Geo Blocker, Geo Login, Rate Limiter, Login Guard, Query Guard, User Enumeration).
* Trusted-networks URL now defaults to the hosted crawler-nets.conf feed and downloads automatically on install.
* Local blocklist table gained pagination, IP/reason search, and newest-first sorting.
* Geo Blocker's country-index refresh rewritten to stream the download and parse line-by-line instead of holding the full dataset in memory — peak memory cut roughly 64% on the ~357k-range DB-IP dataset.
* IP Sharing's enabled toggle now defaults to on, so reporting goes live as soon as an API key is added.

= 0.1.1 =
* Geo Login, Event Map, Activity Log, Rate Limiter, Malware Scanner modules added.
* Admin menu reorganized into clustered tabs (Overview, Perimeter, Inspection, Detection, Hardening, Ops).
* Telegram alerts now include the site's domain alongside its name.

= 0.1.0 =
* Initial modules: IP Blocklist, Query Guard, Login Guard, Headers, User Enumeration, File Integrity, Vulnerability Scan, Auto Updates, User Watchdog, Hardening, Event Log, Telegram Alerts.
