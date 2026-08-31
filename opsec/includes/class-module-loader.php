<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Discovers and wires up modules under includes/modules/*.
 * Each module dir has a module.php defining a class WPOpsec_Module_<Name>
 * with static activate(), deactivate(), register() methods.
 */
class WPOpsec_Module_Loader {

	/** @var array<string,string> module directory name => class name, in load order */
	/**
	 * Order here drives both activation sequence and admin-menu position
	 * (register()/activate() run in this order, and each module's own
	 * add_submenu_page() call happens in that same sequence) — so this
	 * list is grouped into rough categories for the sidebar, not just
	 * build order. The one hard constraint: vuln-scanner must stay ahead
	 * of auto-update, since "update what was flagged" mode reads the
	 * scanner's last result. Everything else here is free to reorder.
	 */
	private static $modules = array(
		// Overview — read/audit views over the shared events table.
		// event-log first: it owns that table.
		'event-log'       => 'WPOpsec_Module_Event_Log',
		'geo-map'         => 'WPOpsec_Module_Geo_Map',
		'activity-log'    => 'WPOpsec_Module_Activity_Log',

		// Perimeter — blocks by IP/identity before WordPress finishes loading.
		'ip-blocklist'    => 'WPOpsec_Module_IP_Blocklist',
		'geo-blocker'     => 'WPOpsec_Module_Geo_Blocker',
		// geo-login right after geo-blocker: it reuses that module's
		// compiled country dataset and class, so must load after it.
		'geo-login'       => 'WPOpsec_Module_Geo_Login',
		'rate-limiter'    => 'WPOpsec_Module_Rate_Limiter',

		// Request inspection — looks at what a request is doing, not just who it's from.
		'query-guard'     => 'WPOpsec_Module_Query_Guard',
		'login-guard'     => 'WPOpsec_Module_Login_Guard',

		// Integrity & detection — is anything already wrong.
		'file-integrity'  => 'WPOpsec_Module_File_Integrity',
		'malware-scanner' => 'WPOpsec_Module_Malware_Scanner',
		'vuln-scanner'    => 'WPOpsec_Module_Vuln_Scanner',
		'user-watchdog'   => 'WPOpsec_Module_User_Watchdog',

		// Hardening — reduces what an attacker can do after getting in.
		'headers'         => 'WPOpsec_Module_Headers',
		'user-enum'       => 'WPOpsec_Module_User_Enum',
		'hardening'       => 'WPOpsec_Module_Hardening',

		// Ops — keeping the above current and knowing when it fires.
		'auto-update'     => 'WPOpsec_Module_Auto_Update',
		'telegram-alerts' => 'WPOpsec_Module_Telegram_Alerts',
	);

	public static function init() {
		self::ensure_mu_loader_current();

		// The mu-plugin WordPress loaded this request is whatever was on disk
		// when the request started. Right after a plugin update that's the
		// *previous* version, so helpers the new module code calls may not be
		// defined yet — the copy above only fixes the next request. Load the
		// fresh file now if anything is missing. require_once dedups by path,
		// so this is a no-op once the current file is already loaded.
		if ( ! function_exists( 'wpopsec_log_event' ) && file_exists( WPOPSEC_MU_DEST ) ) {
			require_once WPOPSEC_MU_DEST;
		}

		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ), 5 );
		WPOpsec_Menu_Router::register();

		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'register' ) ) {
				call_user_func( array( $class, 'register' ) );
			}
		}
	}

	public static function activate() {
		self::copy_mu_loader();

		// Guarantee the shared helpers (wpopsec_local_blocklist_add() etc.)
		// are defined in *this* process before module activate() hooks run.
		// Normal bootstrap loads this file as an actual mu-plugin before
		// plugins_loaded fires, but on a fresh/re-activation the file may
		// not have existed yet when that happened this same request —
		// require_once dedups by path, so this is a no-op when it's already
		// loaded and a real load when it wasn't.
		require_once WPOPSEC_MU_DEST;

		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'activate' ) ) {
				call_user_func( array( $class, 'activate' ) );
			}
		}
	}

	public static function deactivate() {
		foreach ( self::$modules as $module => $class ) {
			self::load_module( $module );
			if ( method_exists( $class, 'deactivate' ) ) {
				call_user_func( array( $class, 'deactivate' ) );
			}
		}

		self::remove_mu_loader();
	}

	public static function admin_menu() {
		add_menu_page(
			'Opsec',
			'Opsec',
			'manage_options',
			'wp-opsec',
			array( __CLASS__, 'render_dashboard' ),
			'dashicons-shield'
		);
	}

	/**
	 * Module status cards. Each entry describes one module's current posture:
	 * `level` drives the colour (good / warn / bad / off) and is what the
	 * overall score is computed from.
	 */
	private static function status_cards() {
		$ip_mode  = get_option( 'wpopsec_ip_blocklist_mode', 'log' );
		$qg_mode  = get_option( 'wpopsec_query_guard_mode', 'log' );
		$lg_on    = (bool) get_option( 'wpopsec_login_guard_enabled', true );
		$headers  = class_exists( 'WPOpsec_Module_Headers' ) ? WPOpsec_Module_Headers::build() : array();
		$ue_on    = (bool) get_option( 'wpopsec_user_enum_block_author_scan', true );
		$fi_base  = (int) get_option( 'wpopsec_integrity_baseline_at', 0 );
		$vuln     = get_option( 'wpopsec_vuln_last_result', array() );
		$au_plug  = get_option( 'wpopsec_auto_update_plugins', 'flagged' );
		$uw_alert = count( (array) get_option( 'wpopsec_user_watchdog_alerts', array() ) );
		$hidden   = count( (array) ( get_option( 'wpopsec_hardening_hidden_result', array() )['hidden'] ?? array() ) );
		$editor   = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;

		$vuln_findings = count( (array) ( $vuln['findings'] ?? array() ) );
		$integrity     = self::integrity_issue_count();

		$mal_last     = get_option( 'wpopsec_malware_last_result', array() );
		$mal_findings = count( (array) ( $mal_last['findings'] ?? array() ) );
		$geo_stats    = get_option( 'wpopsec_geo_stats', array() );
		$geo_selected = count( (array) get_option( 'wpopsec_geo_countries', array() ) );
		$geo_enforce  = get_option( 'wpopsec_geo_enforce_mode', 'log' );
		$gl_selected  = count( (array) get_option( 'wpopsec_geo_login_countries', array() ) );
		$gl_enforce   = get_option( 'wpopsec_geo_login_enforce_mode', 'log' );
		$al_count     = count( (array) get_option( 'wpopsec_activity_categories', array( 'content', 'plugins_themes', 'settings' ) ) );
		$rl_on        = (bool) get_option( 'wpopsec_ratelimit_enabled', true );
		$rl_mode      = get_option( 'wpopsec_ratelimit_mode', 'log' );

		return array(
			array(
				'key'   => 'ip-blocklist',
				'title' => 'IP Blocklist',
				'icon'  => 'shield-alt',
				'state' => 'block' === $ip_mode ? 'Blocking' : 'Log only',
				'level' => 'block' === $ip_mode ? 'good' : 'warn',
				'note'  => sprintf(
					'%s ranges loaded',
					number_format_i18n( (int) ( get_option( 'wpopsec_ip_blocklist_stats', array() )['count_merged'] ?? 0 ) )
				),
			),
			array(
				'key'   => 'query-guard',
				'title' => 'Query Guard',
				'icon'  => 'filter',
				'state' => 'block' === $qg_mode ? 'Blocking' : 'Log only',
				'level' => 'block' === $qg_mode ? 'good' : 'warn',
				'note'  => get_option( 'wpopsec_query_guard_scan_post', true ) ? 'GET + POST scanning' : 'GET only',
			),
			array(
				'key'   => 'login-guard',
				'title' => 'Login Guard',
				'icon'  => 'lock',
				'state' => $lg_on ? 'Enabled' : 'Disabled',
				'level' => $lg_on ? 'good' : 'bad',
				'note'  => sprintf(
					'%d fails / %d min',
					(int) get_option( 'wpopsec_login_guard_max_fails', 8 ),
					(int) get_option( 'wpopsec_login_guard_window_min', 15 )
				),
			),
			array(
				'key'   => 'headers',
				'title' => 'Security Headers',
				'icon'  => 'shield',
				'state' => $headers ? sprintf( '%d active', count( $headers ) ) : 'None',
				'level' => $headers ? 'good' : 'bad',
				'note'  => isset( $headers['Strict-Transport-Security'] ) ? 'HSTS on' : 'HSTS off',
			),
			array(
				'key'   => 'user-enum',
				'title' => 'User Enumeration',
				'icon'  => 'hidden',
				'state' => $ue_on ? 'Protected' : 'Open',
				'level' => $ue_on ? 'good' : 'bad',
				'note'  => get_option( 'wpopsec_user_enum_block_rest_users', true ) ? 'REST users locked' : 'REST users public',
			),
			array(
				'key'   => 'file-integrity',
				'title' => 'File Integrity',
				'icon'  => 'media-code',
				'state' => $integrity > 0 ? sprintf( '%d change(s)', $integrity ) : ( $fi_base ? 'Clean' : 'No baseline' ),
				'level' => $integrity > 0 ? 'bad' : ( $fi_base ? 'good' : 'warn' ),
				'note'  => $fi_base ? sprintf( 'baseline %s', date_i18n( 'M j', $fi_base ) ) : 'take a baseline',
			),
			array(
				'key'   => 'vuln-scanner',
				'title' => 'Vulnerability Scan',
				'icon'  => 'search',
				'state' => $vuln ? ( $vuln_findings ? sprintf( '%d flagged', $vuln_findings ) : 'Clean' ) : 'Not run',
				'level' => $vuln ? ( $vuln_findings ? 'bad' : 'good' ) : 'warn',
				'note'  => $vuln ? sprintf( '%d components checked', (int) ( $vuln['scanned_count'] ?? 0 ) ) : 'never scanned',
			),
			array(
				'key'   => 'auto-update',
				'title' => 'Auto Updates',
				'icon'  => 'update',
				'state' => 'off' === $au_plug ? 'Plugins off' : ( 'all' === $au_plug ? 'All plugins' : 'Flagged only' ),
				'level' => 'off' === $au_plug ? 'warn' : 'good',
				'note'  => sprintf( 'core: %s', get_option( 'wpopsec_auto_update_core', 'minor' ) ),
			),
			array(
				'key'   => 'user-watchdog',
				'title' => 'User Watchdog',
				'icon'  => 'admin-users',
				'state' => $uw_alert ? sprintf( '%d alert(s)', $uw_alert ) : 'Clear',
				'level' => $uw_alert ? 'bad' : 'good',
				'note'  => sprintf(
					'%d privileged account(s)',
					count( (array) get_option( 'wpopsec_user_watchdog_snapshot', array() ) )
				),
			),
			array(
				'key'   => 'hardening',
				'title' => 'Hardening',
				'icon'  => 'admin-tools',
				'state' => $hidden ? sprintf( '%d hidden plugin(s)', $hidden ) : ( $editor ? 'Editor off' : 'Editor on' ),
				'level' => $hidden ? 'bad' : ( $editor ? 'good' : 'warn' ),
				'note'  => class_exists( 'WPOpsec_Module_Hardening' ) && WPOpsec_Module_Hardening::uploads_guard_active()
					? 'uploads guarded'
					: 'uploads unguarded',
			),
			array(
				'key'   => 'telegram-alerts',
				'title' => 'Telegram Alerts',
				'icon'  => 'testimonial',
				'state' => get_option( 'wpopsec_telegram_enabled', false ) ? 'Enabled' : 'Disabled',
				'level' => get_option( 'wpopsec_telegram_enabled', false )
					? ( get_option( 'wpopsec_telegram_chat_id', '' ) ? 'good' : 'warn' )
					: 'warn',
				'note'  => sprintf( 'alerts above %d', (int) get_option( 'wpopsec_telegram_threshold', 15 ) ),
			),
			array(
				'key'   => 'malware-scanner',
				'title' => 'Malware Scanner',
				'icon'  => 'warning',
				'state' => $mal_last ? ( $mal_findings ? sprintf( '%d finding(s)', $mal_findings ) : 'Clean' ) : 'Not run',
				'level' => $mal_last ? ( $mal_findings ? 'bad' : 'good' ) : 'warn',
				'note'  => $mal_last ? sprintf( '%d file(s) scanned', (int) ( $mal_last['scanned_count'] ?? 0 ) ) : 'never scanned',
			),
			array(
				'key'   => 'geo-blocker',
				'title' => 'Geo Blocker',
				'icon'  => 'admin-site-alt3',
				'state' => $geo_selected ? sprintf( '%d country(ies)', $geo_selected ) : 'Not configured',
				'level' => $geo_selected ? ( 'block' === $geo_enforce ? 'good' : 'warn' ) : 'warn',
				'note'  => $geo_stats ? sprintf( '%s ranges indexed', number_format_i18n( (int) ( $geo_stats['count'] ?? 0 ) ) ) : 'no dataset yet',
			),
			array(
				'key'   => 'geo-login',
				'title' => 'Geo Login',
				'icon'  => 'lock',
				'state' => $gl_selected ? sprintf( '%d country(ies)', $gl_selected ) : 'Not configured',
				'level' => $gl_selected ? ( 'block' === $gl_enforce ? 'good' : 'warn' ) : 'warn',
				'note'  => 'wp-login.php only',
			),
			array(
				'key'   => 'activity-log',
				'title' => 'Activity Log',
				'icon'  => 'edit-page',
				'state' => $al_count ? sprintf( '%d categor(ies)', $al_count ) : 'Disabled',
				'level' => $al_count ? 'good' : 'warn',
				'note'  => 'posts, plugins, themes, settings',
			),
			array(
				'key'   => 'rate-limiter',
				'title' => 'Rate Limiter',
				'icon'  => 'clock',
				'state' => ! $rl_on ? 'Disabled' : ( 'block' === $rl_mode ? 'Blocking' : 'Log only' ),
				'level' => ! $rl_on ? 'warn' : ( 'block' === $rl_mode ? 'good' : 'warn' ),
				'note'  => sprintf( '%s req/min per IP', number_format_i18n( (int) get_option( 'wpopsec_ratelimit_per_minute', 300 ) ) ),
			),
			array(
				'key'   => 'geo-map',
				'title' => 'Event Map',
				'icon'  => 'admin-site-alt3',
				'state' => class_exists( 'WPOpsec_Module_Geo_Map' ) ? sprintf( '%d countries · 7d', count( WPOpsec_Module_Geo_Map::counts_by_country( 7 ) ) ) : 'Unavailable',
				'level' => 'good', // read-only visualization, nothing to misconfigure
				'note'  => 'blocked + logged events, by country',
			),
		);
	}

	private static function integrity_issue_count() {
		$last = get_option( 'wpopsec_integrity_last_result', array() );
		if ( empty( $last ) ) {
			return 0;
		}
		return count( (array) ( $last['core']['modified'] ?? array() ) )
			+ count( (array) ( $last['core']['missing'] ?? array() ) )
			+ count( (array) ( $last['diff']['added'] ?? array() ) )
			+ count( (array) ( $last['diff']['modified'] ?? array() ) );
	}

	public static function render_dashboard() {
		global $wpdb;

		$table     = wpopsec_events_table();
		$has_table = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;

		$by_module = array();
		$recent    = array();
		$daily     = array();
		$totals    = array( 'blocked' => 0, 'logged' => 0, 'noted' => 0 );
		$worst     = 0;
		$sev_module = array();

		if ( $has_table ) {
			$worst = (int) $wpdb->get_var(
				"SELECT MAX(severity) FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)"
			);

			$sev_rows = $wpdb->get_results(
				"SELECT module, MAX(severity) s FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY) GROUP BY module",
				ARRAY_A
			) ?: array();
			foreach ( $sev_rows as $r ) {
				$sev_module[ $r['module'] ] = (int) $r['s'];
			}
		}

		if ( $has_table ) {
			$counts = $wpdb->get_results(
				"SELECT module, action, COUNT(*) c
				 FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
				 GROUP BY module, action",
				ARRAY_A
			) ?: array();

			foreach ( $counts as $row ) {
				$by_module[ $row['module'] ][ $row['action'] ] = (int) $row['c'];
				if ( isset( $totals[ $row['action'] ] ) ) {
					$totals[ $row['action'] ] += (int) $row['c'];
				}
			}

			$rows = $wpdb->get_results(
				"SELECT DATE(created_at) d, COUNT(*) c
				 FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
				 GROUP BY DATE(created_at)",
				ARRAY_A
			) ?: array();

			$seen = array();
			foreach ( $rows as $r ) {
				$seen[ $r['d'] ] = (int) $r['c'];
			}
			for ( $i = 6; $i >= 0; $i-- ) {
				$day             = date( 'Y-m-d', strtotime( "-{$i} days" ) );
				$daily[ $day ]   = $seen[ $day ] ?? 0;
			}

			$recent = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 12" ) ?: array();
		}

		$cards = self::status_cards();

		// Simple posture score: every module contributes equally, partial
		// credit for "on but not enforcing". It's a nudge toward the weak
		// spots, not a claim of measured risk.
		$score = 0;
		foreach ( $cards as $c ) {
			$score += ( 'good' === $c['level'] ) ? 1 : ( ( 'warn' === $c['level'] ) ? 0.5 : 0 );
		}
		$score   = (int) round( ( $score / max( 1, count( $cards ) ) ) * 100 );
		$s_level = $score >= 85 ? 'good' : ( $score >= 60 ? 'warn' : 'bad' );
		$s_label = $score >= 85 ? 'Strong' : ( $score >= 60 ? 'Needs attention' : 'Weak' );

		$attention = array_values(
			array_filter(
				$cards,
				function ( $c ) {
					return 'good' !== $c['level'];
				}
			)
		);

		// Shared tokens/components first, then the dashboard-only additions.
		WPOpsec_UI::styles();
		self::dashboard_styles();
		?>
		<div class="wrap wpopsec wpopsec-dash">
			<h1 class="wpopsec-title">
				<span class="dashicons dashicons-shield"></span>
				Opsec
			</h1>

			<div class="wpopsec-hero">
				<div class="wpopsec-score wpopsec-score--<?php echo esc_attr( $s_level ); ?>">
					<div class="wpopsec-score__ring" style="--pct:<?php echo esc_attr( $score ); ?>">
						<div class="wpopsec-score__num"><?php echo esc_html( $score ); ?><span>%</span></div>
					</div>
					<div class="wpopsec-score__label"><?php echo esc_html( $s_label ); ?></div>
				</div>

				<div class="wpopsec-hero__stats">
					<div class="wpopsec-stat wpopsec-stat--bad">
						<span class="dashicons dashicons-dismiss"></span>
						<div>
							<strong><?php echo esc_html( number_format_i18n( $totals['blocked'] ) ); ?></strong>
							<span>blocked · 7 days</span>
						</div>
					</div>
					<div class="wpopsec-stat wpopsec-stat--warn">
						<span class="dashicons dashicons-visibility"></span>
						<div>
							<strong><?php echo esc_html( number_format_i18n( $totals['logged'] ) ); ?></strong>
							<span>would block (log only)</span>
						</div>
					</div>
					<?php list( $w_label, $w_color ) = wpopsec_severity_meta( $worst ); ?>
					<div class="wpopsec-stat">
						<span class="dashicons dashicons-warning" style="color:<?php echo esc_attr( $worst ? $w_color : '#646970' ); ?>"></span>
						<div>
							<strong><?php echo $worst ? esc_html( $worst ) . '<span style="font-size:13px;font-weight:400;color:#646970">/20</span>' : '—'; ?></strong>
							<span>worst severity<?php echo $worst ? esc_html( ' · ' . $w_label ) : ''; ?></span>
						</div>
					</div>

					<?php if ( $daily ) : ?>
						<div class="wpopsec-spark">
							<?php
							$max = max( 1, max( $daily ) );
							foreach ( $daily as $day => $n ) :
								$h = max( 3, (int) round( ( $n / $max ) * 46 ) );
								?>
								<span class="wpopsec-spark__bar"
									style="height:<?php echo esc_attr( $h ); ?>px"
									title="<?php echo esc_attr( sprintf( '%s — %d event(s)', date_i18n( 'D j M', strtotime( $day ) ), $n ) ); ?>"></span>
							<?php endforeach; ?>
						</div>
					<?php endif; ?>
				</div>
			</div>

			<?php if ( $attention ) : ?>
				<div class="wpopsec-attention">
					<span class="dashicons dashicons-warning"></span>
					<div>
						<strong>Worth a look:</strong>
						<?php
						$links = array();
						foreach ( $attention as $a ) {
							$links[] = sprintf(
								'<a href="%s">%s <em>(%s)</em></a>',
								esc_url( WPOpsec_Menu_Router::url( $a['key'] ) ),
								esc_html( $a['title'] ),
								esc_html( strtolower( $a['state'] ) )
							);
						}
						echo wp_kses_post( implode( ' · ', $links ) );
						?>
					</div>
				</div>
			<?php endif; ?>

			<h2 class="wpopsec-h2">Modules</h2>
			<div class="wpopsec-grid">
				<?php foreach ( $cards as $card ) : ?>
					<?php
					$blocked = $by_module[ $card['key'] ]['blocked'] ?? 0;
					$logged  = $by_module[ $card['key'] ]['logged'] ?? 0;
					$noted   = $by_module[ $card['key'] ]['noted'] ?? 0;
					$total   = $blocked + $logged + $noted;
					?>
					<a class="wpopsec-card wpopsec-card--<?php echo esc_attr( $card['level'] ); ?>"
						href="<?php echo esc_url( WPOpsec_Menu_Router::url( $card['key'] ) ); ?>">
						<div class="wpopsec-card__top">
							<span class="wpopsec-card__icon dashicons dashicons-<?php echo esc_attr( $card['icon'] ); ?>"></span>
							<span class="wpopsec-card__title"><?php echo esc_html( $card['title'] ); ?></span>
							<?php if ( ! empty( $sev_module[ $card['key'] ] ) ) : ?>
								<?php list( $cs_label, $cs_color ) = wpopsec_severity_meta( $sev_module[ $card['key'] ] ); ?>
								<span class="wpopsec-sevdot"
									style="background:<?php echo esc_attr( $cs_color ); ?>"
									title="<?php echo esc_attr( sprintf( 'Worst severity in 7 days: %d (%s)', $sev_module[ $card['key'] ], $cs_label ) ); ?>"><?php echo esc_html( $sev_module[ $card['key'] ] ); ?></span>
							<?php endif; ?>
						</div>
						<div class="wpopsec-pill"><?php echo esc_html( $card['state'] ); ?></div>
						<div class="wpopsec-card__note"><?php echo esc_html( $card['note'] ); ?></div>
						<div class="wpopsec-card__foot">
							<?php if ( $total ) : ?>
								<?php if ( $blocked ) : ?>
									<span class="wpopsec-chip wpopsec-chip--bad"><?php echo esc_html( number_format_i18n( $blocked ) ); ?> blocked</span>
								<?php endif; ?>
								<?php if ( $logged ) : ?>
									<span class="wpopsec-chip wpopsec-chip--warn"><?php echo esc_html( number_format_i18n( $logged ) ); ?> logged</span>
								<?php endif; ?>
								<?php if ( $noted && ! $blocked && ! $logged ) : ?>
									<span class="wpopsec-chip"><?php echo esc_html( number_format_i18n( $noted ) ); ?> events</span>
								<?php endif; ?>
							<?php else : ?>
								<span class="wpopsec-chip wpopsec-chip--quiet">no activity</span>
							<?php endif; ?>
						</div>
					</a>
				<?php endforeach; ?>
			</div>

			<h2 class="wpopsec-h2">
				Recent activity
				<a class="wpopsec-h2__link" href="<?php echo esc_url( WPOpsec_Menu_Router::url( 'event-log' ) ); ?>">View full log →</a>
			</h2>

			<?php if ( empty( $recent ) ) : ?>
				<div class="wpopsec-empty">
					<span class="dashicons dashicons-yes-alt"></span>
					<p>No events recorded yet. Modules in log-only mode will record here as traffic arrives.</p>
				</div>
			<?php else : ?>
				<table class="wpopsec-table">
					<thead>
						<tr>
							<th style="width:56px">Sev</th>
							<th style="width:130px">Time</th>
							<th style="width:120px">Module</th>
							<th style="width:170px">Event</th>
							<th style="width:90px">Action</th>
							<th style="width:120px">IP</th>
							<th>Detail</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $recent as $row ) : ?>
						<?php list( $rs_label, $rs_color ) = wpopsec_severity_meta( $row->severity ); ?>
						<tr>
							<td>
								<span class="wpopsec-sevdot" style="background:<?php echo esc_attr( $rs_color ); ?>"
									title="<?php echo esc_attr( $rs_label ); ?>"><?php echo esc_html( (int) $row->severity ); ?></span>
							</td>
							<td class="wpopsec-nowrap"><?php echo esc_html( mysql2date( 'M j, H:i', $row->created_at ) ); ?></td>
							<td><span class="wpopsec-mod"><?php echo esc_html( $row->module ); ?></span></td>
							<td><code><?php echo esc_html( $row->event ); ?></code></td>
							<td>
								<?php if ( 'blocked' === $row->action ) : ?>
									<span class="wpopsec-chip wpopsec-chip--bad">blocked</span>
								<?php elseif ( 'logged' === $row->action ) : ?>
									<span class="wpopsec-chip wpopsec-chip--warn">logged</span>
								<?php else : ?>
									<span class="wpopsec-chip wpopsec-chip--quiet">noted</span>
								<?php endif; ?>
							</td>
							<td class="wpopsec-nowrap"><code><?php echo esc_html( $row->ip ); ?></code></td>
							<td class="wpopsec-detail"><?php echo esc_html( $row->detail ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Inline so the dashboard has no external asset dependency — it stays
	 * readable even if the site enforces a strict CSP or blocks outside
	 * requests. Dashicons ship with WordPress admin, so no icon font is
	 * fetched either.
	 */
	private static function dashboard_styles() {
		?>
		<style>
		/* Tokens come from WPOpsec_UI::styles(); only dashboard-specific bits below. */
		.wpopsec-dash .wpopsec-title { display:flex; align-items:center; gap:10px; font-size:23px; margin-bottom:18px; }
		.wpopsec-dash .wpopsec-title .dashicons { font-size:30px; width:30px; height:30px; color:#2271b1; }

		.wpopsec-hero { display:flex; flex-wrap:wrap; gap:26px; align-items:center;
			background:var(--card); border:1px solid var(--line); border-radius:10px;
			padding:20px 24px; margin-bottom:16px; }

		.wpopsec-score { display:flex; flex-direction:column; align-items:center; gap:6px; }
		.wpopsec-score__ring { --pct:0; width:104px; height:104px; border-radius:50%;
			display:grid; place-items:center;
			background:conic-gradient(var(--ring) calc(var(--pct)*1%), #e9eaec 0); }
		.wpopsec-score--good .wpopsec-score__ring { --ring:var(--ok); }
		.wpopsec-score--warn .wpopsec-score__ring { --ring:var(--warn); }
		.wpopsec-score--bad  .wpopsec-score__ring { --ring:var(--bad); }
		.wpopsec-score__num { width:82px; height:82px; border-radius:50%; background:var(--card);
			display:grid; place-items:center; font-size:25px; font-weight:600; color:var(--ink); }
		.wpopsec-score__num span { font-size:13px; font-weight:400; color:var(--muted); }
		.wpopsec-score__label { font-size:12px; font-weight:600; text-transform:uppercase;
			letter-spacing:.6px; color:var(--muted); }

		.wpopsec-hero__stats { display:flex; flex-wrap:wrap; gap:22px; align-items:center; flex:1; }
		.wpopsec-stat { display:flex; align-items:center; gap:10px; }
		.wpopsec-stat .dashicons { font-size:22px; width:22px; height:22px; color:var(--muted); }
		.wpopsec-stat--bad .dashicons { color:var(--bad); }
		.wpopsec-stat--warn .dashicons { color:var(--warn); }
		.wpopsec-stat strong { display:block; font-size:21px; line-height:1.15; color:var(--ink); }
		.wpopsec-stat span:last-child { font-size:12px; color:var(--muted); }

		.wpopsec-spark { display:flex; align-items:flex-end; gap:4px; height:50px;
			margin-left:auto; padding-left:16px; border-left:1px solid var(--line); }
		.wpopsec-spark__bar { width:11px; background:#c3c4c7; border-radius:2px 2px 0 0; cursor:default; }
		.wpopsec-spark__bar:hover { background:#2271b1; }

		.wpopsec-attention { display:flex; gap:10px; align-items:flex-start;
			background:#fcf9e8; border:1px solid #f0e2a1; border-left:4px solid #dba617;
			border-radius:6px; padding:12px 14px; margin-bottom:20px; }
		.wpopsec-attention .dashicons { color:#dba617; }
		.wpopsec-attention a { text-decoration:none; }
		.wpopsec-attention em { color:var(--muted); font-style:normal; font-size:12px; }

		.wpopsec-h2 { display:flex; align-items:baseline; gap:12px; font-size:15px;
			text-transform:uppercase; letter-spacing:.5px; color:var(--muted); margin:24px 0 12px; }
		.wpopsec-h2__link { margin-left:auto; font-size:13px; text-transform:none;
			letter-spacing:0; text-decoration:none; }

		.wpopsec-grid { display:grid; gap:14px;
			grid-template-columns:repeat(auto-fill, minmax(232px, 1fr)); }
		.wpopsec-card { display:block; background:var(--card); border:1px solid var(--line);
			border-top:3px solid var(--accent, #c3c4c7); border-radius:8px; padding:14px 16px;
			text-decoration:none; color:inherit; transition:box-shadow .15s, transform .15s; }
		.wpopsec-card:hover { box-shadow:0 3px 12px rgba(0,0,0,.09); transform:translateY(-1px); }
		.wpopsec-card--good { --accent:var(--ok); }
		.wpopsec-card--warn { --accent:var(--warn); }
		.wpopsec-card--bad  { --accent:var(--bad); }
		.wpopsec-card__top { display:flex; align-items:center; gap:8px; margin-bottom:9px; }
		.wpopsec-card__icon { font-size:19px; width:19px; height:19px; color:var(--accent, #646970); }
		.wpopsec-card__title { font-weight:600; font-size:14px; color:var(--ink); }
		.wpopsec-card__note { font-size:12px; color:var(--muted); margin-top:7px; }
		.wpopsec-sevdot { margin-left:auto; display:inline-grid; place-items:center; min-width:22px;
			height:20px; padding:0 5px; border-radius:4px; color:#fff; font-size:11px;
			font-weight:700; font-variant-numeric:tabular-nums; }
		.wpopsec-card__foot { margin-top:11px; display:flex; gap:6px; flex-wrap:wrap; }

		.wpopsec-pill { display:inline-block; font-size:12px; font-weight:600; padding:3px 9px;
			border-radius:11px; background:#f0f0f1; color:var(--ink); }
		.wpopsec-card--good .wpopsec-pill { background:#e5f5ee; color:var(--ok); }
		.wpopsec-card--warn .wpopsec-pill { background:#fcf3e3; color:var(--warn); }
		.wpopsec-card--bad  .wpopsec-pill { background:#fdeaf1; color:var(--bad); }

		.wpopsec-chip { display:inline-block; font-size:11px; padding:2px 7px; border-radius:9px;
			background:#f0f0f1; color:var(--muted); }
		.wpopsec-chip--bad { background:#fdeaf1; color:var(--bad); font-weight:600; }
		.wpopsec-chip--warn { background:#fcf3e3; color:var(--warn); font-weight:600; }
		.wpopsec-chip--quiet { background:transparent; color:#8c8f94; padding-left:0; }

		.wpopsec-table { width:100%; border-collapse:separate; border-spacing:0;
			background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
		.wpopsec-table th { text-align:left; font-size:11px; text-transform:uppercase;
			letter-spacing:.5px; color:var(--muted); padding:9px 12px;
			background:var(--bg); border-bottom:1px solid var(--line); }
		.wpopsec-table td { padding:9px 12px; border-bottom:1px solid #f0f0f1; font-size:13px;
			vertical-align:middle; }
		.wpopsec-table tr:last-child td { border-bottom:0; }
		.wpopsec-table tbody tr:hover { background:#fafafa; }
		.wpopsec-table code { font-size:12px; background:#f6f7f7; padding:1px 5px; border-radius:3px; }
		.wpopsec-nowrap { white-space:nowrap; }
		.wpopsec-detail { color:var(--muted); font-size:12px; word-break:break-word; }
		.wpopsec-mod { font-size:12px; font-weight:600; color:#2271b1; }

		.wpopsec-empty { text-align:center; padding:34px; background:var(--card);
			border:1px dashed var(--line); border-radius:8px; color:var(--muted); }
		.wpopsec-empty .dashicons { font-size:30px; width:30px; height:30px; color:var(--ok); }

		@media screen and (max-width:782px) {
			.wpopsec-spark { margin-left:0; border-left:0; padding-left:0; }
		}
		</style>
		<?php
	}


	private static function load_module( $module ) {
		$file = WPOPSEC_PLUGIN_DIR . "includes/modules/{$module}/module.php";
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}

	private static function copy_mu_loader() {
		if ( ! file_exists( WPMU_PLUGIN_DIR ) ) {
			wp_mkdir_p( WPMU_PLUGIN_DIR );
		}
		copy( WPOPSEC_MU_SOURCE, WPOPSEC_MU_DEST );
	}

	private static function remove_mu_loader() {
		if ( file_exists( WPOPSEC_MU_DEST ) ) {
			unlink( WPOPSEC_MU_DEST );
		}
	}

	/**
	 * Keep the deployed mu-plugin file in sync with the version shipped in
	 * this plugin (e.g. after a plugin update), without requiring reactivation.
	 */
	private static function ensure_mu_loader_current() {
		if ( ! file_exists( WPOPSEC_MU_DEST )
			|| md5_file( WPOPSEC_MU_DEST ) !== md5_file( WPOPSEC_MU_SOURCE ) ) {
			self::copy_mu_loader();
		}
	}
}
