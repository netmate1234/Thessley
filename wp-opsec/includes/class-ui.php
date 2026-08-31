<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared presentation helpers for every WP Opsec screen.
 *
 * All styling is inlined and all icons come from the Dashicons font that
 * wp-admin already loads, so the plugin's own screens keep working under a
 * strict Content-Security-Policy — which this plugin can itself set.
 */
class WPOpsec_UI {

	/** @var bool emitted once per request */
	private static $styles_done = false;

	/** Page-level icon + copy for each screen, keyed by module. */
	public static function meta( $key ) {
		$map = array(
			'dashboard'      => array( 'shield', 'WP Opsec', '' ),
			'event-log'      => array( 'list-view', 'Event Log', 'Everything the modules have seen, newest first. Severity runs 1–20; anything 18+ means something already happened rather than an attempt that was stopped.' ),
			'ip-blocklist'   => array( 'shield-alt', 'IP Blocklist', 'Blocks traffic from IPs on public reputation feeds, plus a local list other modules can escalate into.' ),
			'query-guard'    => array( 'filter', 'Query Guard', 'Inspects query strings and request bodies for attack signatures before WordPress finishes loading.' ),
			'login-guard'    => array( 'lock', 'Login Guard', 'Rate-limits failed logins per IP. Your LAN and anything in the trusted networks file is never locked out.' ),
			'headers'        => array( 'shield', 'Security Headers', 'Response headers that harden the browser side. The two that can break a site are off by default.' ),
			'user-enum'      => array( 'hidden', 'User Enumeration', 'Stops anonymous visitors harvesting valid usernames — which halves the work of a brute force.' ),
			'file-integrity' => array( 'media-code', 'File Integrity', 'Verifies core against WordPress.org checksums, and plugins/themes against a local baseline.' ),
			'vuln-scanner'   => array( 'search', 'Vulnerability Scan', 'Flags outdated, removed and unmaintained components. 91% of WordPress vulnerabilities live in plugins.' ),
			'auto-update'    => array( 'update', 'Auto Updates', 'About 60% of compromises exploit an already-patched flaw. Installing the update is the fix.' ),
			'user-watchdog'  => array( 'admin-users', 'User Watchdog', 'Watches privileged accounts. A hidden administrator is how a backdoor survives removal of the code that planted it.' ),
			'hardening'      => array( 'admin-tools', 'Hardening', 'Removes the tools an attacker reaches for after getting in.' ),
			'telegram-alerts' => array( 'testimonial', 'Telegram Alerts', 'Sends a real-time Telegram message when an event exceeds a severity threshold. The Event Log records everything regardless of this setting.' ),
			'malware-scanner' => array( 'warning', 'Malware Scanner', 'Scans plugin, theme and upload files for webshell, obfuscation and injected-spam signatures.' ),
			'geo-blocker'     => array( 'admin-site-alt3', 'Geo Blocker', 'Blocks or allows traffic by country, using a compiled IP-to-country dataset checked at the early gate.' ),
			'activity-log'    => array( 'edit-page', 'Activity Log', 'Records who published, deleted, installed or changed what — the mundane audit trail, not attack detections.' ),
			'rate-limiter'    => array( 'clock', 'Rate Limiter', 'Throttles requests per IP site-wide, and escalates sustained floods to the local IP blocklist.' ),
			'geo-map'         => array( 'admin-site-alt3', 'Event Map', 'Blocked and logged events tinted on a world map by country, reusing Geo Blocker\'s dataset. Read-only — nothing here affects enforcement.' ),
		);

		return $map[ $key ] ?? array( 'shield', 'WP Opsec', '' );
	}

	/** Opens .wrap and renders the page header. Pair with self::close(). */
	public static function open( $key ) {
		self::styles();
		list( $icon, $title, $desc ) = self::meta( $key );
		?>
		<div class="wrap wpopsec">
			<div class="wpopsec-head">
				<span class="wpopsec-head__icon dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
				<div>
					<h1><?php echo esc_html( $title ); ?></h1>
					<?php if ( $desc ) : ?>
						<p class="wpopsec-head__desc"><?php echo esc_html( $desc ); ?></p>
					<?php endif; ?>
				</div>
			</div>
		<?php
	}

	public static function close() {
		echo '</div>';
	}

	/**
	 * @param string $type success|warning|error|info
	 */
	public static function notice( $type, $message, $allow_html = false ) {
		$icons = array(
			'success' => 'yes-alt',
			'warning' => 'warning',
			'error'   => 'dismiss',
			'info'    => 'info-outline',
		);
		$icon = $icons[ $type ] ?? 'info-outline';
		?>
		<div class="wpopsec-notice wpopsec-notice--<?php echo esc_attr( $type ); ?>">
			<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
			<div><?php echo $allow_html ? wp_kses_post( $message ) : esc_html( $message ); ?></div>
		</div>
		<?php
	}

	/** Opens a titled section card. Pair with self::section_end(). */
	public static function section( $title, $icon = '', $subtitle = '' ) {
		?>
		<section class="wpopsec-section">
			<header class="wpopsec-section__head">
				<?php if ( $icon ) : ?>
					<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
				<?php endif; ?>
				<h2><?php echo esc_html( $title ); ?></h2>
				<?php if ( $subtitle ) : ?>
					<span class="wpopsec-section__sub"><?php echo esc_html( $subtitle ); ?></span>
				<?php endif; ?>
			</header>
			<div class="wpopsec-section__body">
		<?php
	}

	public static function section_end() {
		echo '</div></section>';
	}

	/**
	 * Status badge.
	 *
	 * @param string $tone good|warn|bad|quiet
	 */
	public static function badge( $text, $tone = 'quiet', $icon = '' ) {
		printf(
			'<span class="wpopsec-badge wpopsec-badge--%s">%s%s</span>',
			esc_attr( $tone ),
			$icon ? '<span class="dashicons dashicons-' . esc_attr( $icon ) . '"></span>' : '',
			esc_html( $text )
		);
	}

	/** Compact key/value tiles for a status row. */
	public static function tiles( array $tiles ) {
		echo '<div class="wpopsec-tiles">';
		foreach ( $tiles as $tile ) {
			printf(
				'<div class="wpopsec-tile wpopsec-tile--%s"><span class="dashicons dashicons-%s"></span><div><strong>%s</strong><span>%s</span></div></div>',
				esc_attr( $tile['tone'] ?? 'quiet' ),
				esc_attr( $tile['icon'] ?? 'marker' ),
				esc_html( $tile['value'] ),
				esc_html( $tile['label'] )
			);
		}
		echo '</div>';
	}

	/** A labelled row inside a settings card (replaces .form-table). */
	public static function row( $label, $body_cb, $help = '' ) {
		?>
		<div class="wpopsec-row">
			<div class="wpopsec-row__label"><?php echo esc_html( $label ); ?></div>
			<div class="wpopsec-row__field">
				<?php call_user_func( $body_cb ); ?>
				<?php if ( $help ) : ?>
					<p class="wpopsec-help"><?php echo wp_kses_post( $help ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	public static function severity_badge( $severity, $with_label = true ) {
		list( $label, $color ) = wpopsec_severity_meta( $severity );
		printf(
			'<span class="wpopsec-sev"><span class="wpopsec-sev__num" style="background:%s">%d</span>%s</span>',
			esc_attr( $color ),
			(int) $severity,
			$with_label ? '<span class="wpopsec-sev__label">' . esc_html( $label ) . '</span>' : ''
		);
	}

	public static function styles() {
		if ( self::$styles_done ) {
			return;
		}
		self::$styles_done = true;
		?>
		<style>
		.wpopsec { --ok:#00875a; --warn:#b26e00; --bad:#c9356a; --crit:#8b0a3e;
			--ink:#1d2327; --muted:#646970; --line:#dcdcde; --card:#fff; --bg:#f6f7f7; --blue:#2271b1; }
		.wpopsec { max-width:1180px; }

		/* Header */
		.wpopsec-head { display:flex; gap:14px; align-items:flex-start; margin:6px 0 20px; }
		.wpopsec-head__icon { font-size:32px; width:32px; height:32px; color:var(--blue); flex:none; margin-top:2px; }
		.wpopsec-head h1 { margin:0; padding:0; font-size:23px; line-height:1.3; }
		.wpopsec-head__desc { margin:5px 0 0; color:var(--muted); max-width:72ch; font-size:13px; }

		/* Notices */
		.wpopsec-notice { display:flex; gap:10px; align-items:flex-start; padding:11px 14px;
			border-radius:6px; margin:0 0 16px; border:1px solid; font-size:13px; }
		.wpopsec-notice .dashicons { flex:none; }
		.wpopsec-notice p { margin:.3em 0; }
		.wpopsec-notice ul { margin:.4em 0 .4em 1.4em; list-style:disc; }
		.wpopsec-notice--success { background:#edf7f2; border-color:#b6e0cb; color:#0a5c3e; }
		.wpopsec-notice--success .dashicons { color:var(--ok); }
		.wpopsec-notice--warning { background:#fcf9e8; border-color:#f0e2a1; color:#6b5200; }
		.wpopsec-notice--warning .dashicons { color:#dba617; }
		.wpopsec-notice--error   { background:#fdf0f4; border-color:#f3c2d2; color:#8b0a3e; }
		.wpopsec-notice--error .dashicons { color:var(--bad); }
		.wpopsec-notice--info    { background:#f0f6fc; border-color:#c5d9ed; color:#124f80; }
		.wpopsec-notice--info .dashicons { color:var(--blue); }

		/* Sections */
		.wpopsec-section { background:var(--card); border:1px solid var(--line);
			border-radius:8px; margin:0 0 18px; overflow:hidden; }
		.wpopsec-section__head { display:flex; align-items:center; gap:9px;
			padding:12px 16px; border-bottom:1px solid var(--line); background:var(--bg); }
		.wpopsec-section__head .dashicons { color:var(--muted); font-size:18px; width:18px; height:18px; }
		.wpopsec-section__head h2 { margin:0; padding:0; font-size:14px; font-weight:600; color:var(--ink); }
		.wpopsec-section__sub { margin-left:auto; font-size:12px; color:var(--muted); }
		.wpopsec-section__body { padding:16px; }
		.wpopsec-section__body > :first-child { margin-top:0; }
		.wpopsec-section__body > :last-child { margin-bottom:0; }

		/* Settings rows */
		.wpopsec-row { display:flex; gap:20px; padding:14px 0; border-bottom:1px solid #f0f0f1; }
		.wpopsec-row:first-child { padding-top:0; }
		.wpopsec-row:last-child { border-bottom:0; padding-bottom:0; }
		.wpopsec-row__label { flex:0 0 190px; font-weight:600; font-size:13px; color:var(--ink); padding-top:2px; }
		.wpopsec-row__field { flex:1; min-width:0; }
		.wpopsec-row__field label { display:inline-flex; align-items:flex-start; gap:7px; font-size:13px; }
		.wpopsec-row__field > label { display:flex; margin-bottom:6px; }
		.wpopsec-help { margin:6px 0 0; color:var(--muted); font-size:12px; max-width:74ch; }
		.wpopsec-help code { font-size:11px; background:var(--bg); padding:1px 4px; border-radius:3px; }

		/* Badges + tiles */
		.wpopsec-badge { display:inline-flex; align-items:center; gap:4px; font-size:12px;
			font-weight:600; padding:3px 9px; border-radius:11px; background:#f0f0f1; color:var(--muted); }
		.wpopsec-badge .dashicons { font-size:14px; width:14px; height:14px; }
		.wpopsec-badge--good { background:#e5f5ee; color:var(--ok); }
		.wpopsec-badge--warn { background:#fcf3e3; color:var(--warn); }
		.wpopsec-badge--bad  { background:#fdeaf1; color:var(--bad); }

		.wpopsec-tiles { display:flex; flex-wrap:wrap; gap:20px; }
		.wpopsec-tile { display:flex; align-items:center; gap:10px; }
		.wpopsec-tile .dashicons { font-size:21px; width:21px; height:21px; color:var(--muted); }
		.wpopsec-tile--good .dashicons { color:var(--ok); }
		.wpopsec-tile--warn .dashicons { color:var(--warn); }
		.wpopsec-tile--bad .dashicons  { color:var(--bad); }
		.wpopsec-tile strong { display:block; font-size:19px; line-height:1.2; color:var(--ink); }
		.wpopsec-tile span:last-child { font-size:12px; color:var(--muted); }

		/* Severity */
		.wpopsec-sev { display:inline-flex; align-items:center; gap:6px; }
		.wpopsec-sev__num { display:inline-grid; place-items:center; min-width:26px; height:22px;
			padding:0 5px; border-radius:4px; color:#fff; font-weight:700; font-size:12px;
			font-variant-numeric:tabular-nums; }
		.wpopsec-sev__label { font-size:11px; text-transform:uppercase; letter-spacing:.4px; color:var(--muted); }

		/* Tables */
		.wpopsec-table { width:100%; border-collapse:separate; border-spacing:0; }
		.wpopsec-table th { text-align:left; font-size:11px; text-transform:uppercase;
			letter-spacing:.5px; color:var(--muted); padding:8px 10px;
			background:var(--bg); border-bottom:1px solid var(--line); }
		.wpopsec-table td { padding:9px 10px; border-bottom:1px solid #f0f0f1; font-size:13px; vertical-align:middle; }
		.wpopsec-table tr:last-child td { border-bottom:0; }
		.wpopsec-table tbody tr:hover { background:#fafafa; }
		.wpopsec-table code { font-size:12px; background:var(--bg); padding:1px 5px; border-radius:3px; }
		.wpopsec-nowrap { white-space:nowrap; }
		.wpopsec-muted { color:var(--muted); font-size:12px; }

		/* Scroll container for long lists */
		.wpopsec-scroll { max-height:280px; overflow:auto; border:1px solid var(--line);
			border-radius:6px; padding:10px 12px; background:var(--bg); }
		.wpopsec-scroll label { display:flex; margin-bottom:4px; }

		/* File lists */
		.wpopsec-files { margin:0 0 10px; }
		.wpopsec-files__title { font-weight:600; margin:0 0 4px; }
		.wpopsec-files ul { margin:0 0 0 1.4em; list-style:disc; }
		.wpopsec-files code { font-size:12px; }

		/* Empty state */
		.wpopsec-empty { text-align:center; padding:28px; color:var(--muted); }
		.wpopsec-empty .dashicons { font-size:28px; width:28px; height:28px; color:var(--ok); }
		.wpopsec-empty p { margin:.5em 0 0; }

		.wpopsec .button + .button { margin-left:6px; }
		.wpopsec form { margin:0; }
		.wpopsec-actions { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }

		@media screen and (max-width:782px) {
			.wpopsec-row { flex-direction:column; gap:6px; }
			.wpopsec-row__label { flex:none; }
		}
		</style>
		<?php
	}
}
