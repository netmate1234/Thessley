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
	private static $modules = array(
		// event-log first: it owns the table the others log into.
		'event-log'      => 'WPOpsec_Module_Event_Log',
		'ip-blocklist'   => 'WPOpsec_Module_IP_Blocklist',
		'query-guard'    => 'WPOpsec_Module_Query_Guard',
		'login-guard'    => 'WPOpsec_Module_Login_Guard',
		'headers'        => 'WPOpsec_Module_Headers',
		'user-enum'      => 'WPOpsec_Module_User_Enum',
		'file-integrity' => 'WPOpsec_Module_File_Integrity',
		'vuln-scanner'   => 'WPOpsec_Module_Vuln_Scanner',
		// vuln-scanner before auto-update: "update what was flagged" mode
		// reads the scanner's last result.
		'auto-update'    => 'WPOpsec_Module_Auto_Update',
		'user-watchdog'  => 'WPOpsec_Module_User_Watchdog',
		'hardening'      => 'WPOpsec_Module_Hardening',
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
			'WP Opsec',
			'WP Opsec',
			'manage_options',
			'wp-opsec',
			array( __CLASS__, 'render_dashboard' ),
			'dashicons-shield'
		);
	}

	public static function render_dashboard() {
		global $wpdb;

		$table  = wpopsec_events_table();
		$counts = array();
		$recent = array();

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table ) {
			$counts = $wpdb->get_results(
				"SELECT module, action, COUNT(*) c
				 FROM {$table}
				 WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
				 GROUP BY module, action",
				ARRAY_A
			) ?: array();

			$recent = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 10" ) ?: array();
		}

		$by_module = array();
		foreach ( $counts as $row ) {
			$by_module[ $row['module'] ][ $row['action'] ] = (int) $row['c'];
		}

		$cards = array(
			array(
				'title' => 'IP Blocklist',
				'page'  => 'wp-opsec-ip-blocklist',
				'state' => 'block' === get_option( 'wpopsec_ip_blocklist_mode', 'log' ) ? 'Blocking' : 'Log only',
				'on'    => 'block' === get_option( 'wpopsec_ip_blocklist_mode', 'log' ),
				'note'  => sprintf( '%s ranges', number_format_i18n( (int) ( get_option( 'wpopsec_ip_blocklist_stats', array() )['count_merged'] ?? 0 ) ) ),
				'key'   => 'ip-blocklist',
			),
			array(
				'title' => 'Query Guard',
				'page'  => 'wp-opsec-query-guard',
				'state' => 'block' === get_option( 'wpopsec_query_guard_mode', 'log' ) ? 'Blocking' : 'Log only',
				'on'    => 'block' === get_option( 'wpopsec_query_guard_mode', 'log' ),
				'note'  => get_option( 'wpopsec_query_guard_block_xmlrpc', false ) ? 'xmlrpc blocked' : 'xmlrpc allowed',
				'key'   => 'query-guard',
			),
			array(
				'title' => 'Login Guard',
				'page'  => 'wp-opsec-login-guard',
				'state' => get_option( 'wpopsec_login_guard_enabled', true ) ? 'Enabled' : 'Disabled',
				'on'    => (bool) get_option( 'wpopsec_login_guard_enabled', true ),
				'note'  => sprintf( '%d fails / %d min', (int) get_option( 'wpopsec_login_guard_max_fails', 8 ), (int) get_option( 'wpopsec_login_guard_window_min', 15 ) ),
				'key'   => 'login-guard',
			),
			array(
				'title' => 'Security Headers',
				'page'  => 'wp-opsec-headers',
				'state' => class_exists( 'WPOpsec_Module_Headers' ) && WPOpsec_Module_Headers::build() ? 'Active' : 'None',
				'on'    => class_exists( 'WPOpsec_Module_Headers' ) && (bool) WPOpsec_Module_Headers::build(),
				'note'  => class_exists( 'WPOpsec_Module_Headers' ) ? sprintf( '%d header(s)', count( WPOpsec_Module_Headers::build() ) ) : '',
				'key'   => 'headers',
			),
			array(
				'title' => 'User Enumeration',
				'page'  => 'wp-opsec-user-enum',
				'state' => get_option( 'wpopsec_user_enum_block_author_scan', true ) ? 'Protected' : 'Open',
				'on'    => (bool) get_option( 'wpopsec_user_enum_block_author_scan', true ),
				'note'  => get_option( 'wpopsec_user_enum_block_rest_users', true ) ? 'REST users locked' : 'REST users public',
				'key'   => 'user-enum',
			),
			array(
				'title' => 'File Integrity',
				'page'  => 'wp-opsec-file-integrity',
				'state' => get_option( 'wpopsec_integrity_baseline_at', 0 ) ? 'Baselined' : 'No baseline',
				'on'    => (bool) get_option( 'wpopsec_integrity_baseline_at', 0 ),
				'note'  => self::integrity_note(),
				'key'   => 'file-integrity',
			),
			array(
				'title' => 'Vulnerability Scan',
				'page'  => 'wp-opsec-vuln-scanner',
				'state' => get_option( 'wpopsec_vuln_last_result', array() ) ? 'Scanned' : 'Not run',
				'on'    => (bool) get_option( 'wpopsec_vuln_last_result', array() ),
				'note'  => self::vuln_note(),
				'key'   => 'vuln-scanner',
			),
			array(
				'title' => 'Auto Updates',
				'page'  => 'wp-opsec-auto-update',
				'state' => 'off' === get_option( 'wpopsec_auto_update_plugins', 'flagged' ) ? 'Plugins off' : 'Plugins on',
				'on'    => 'off' !== get_option( 'wpopsec_auto_update_plugins', 'flagged' ),
				'note'  => sprintf( 'core: %s', get_option( 'wpopsec_auto_update_core', 'minor' ) ),
				'key'   => 'auto-update',
			),
			array(
				'title' => 'User Watchdog',
				'page'  => 'wp-opsec-user-watchdog',
				'state' => self::watchdog_state(),
				'on'    => ! count( (array) get_option( 'wpopsec_user_watchdog_alerts', array() ) ),
				'note'  => sprintf( '%d privileged account(s)', count( (array) get_option( 'wpopsec_user_watchdog_snapshot', array() ) ) ),
				'key'   => 'user-watchdog',
			),
			array(
				'title' => 'Hardening',
				'page'  => 'wp-opsec-hardening',
				'state' => ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) ? 'Editor off' : 'Editor on',
				'on'    => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
				'note'  => self::hardening_note(),
				'key'   => 'hardening',
			),
		);
		?>
		<div class="wrap">
			<h1>WP Opsec</h1>

			<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;margin:1.5em 0">
				<?php foreach ( $cards as $card ) : ?>
					<div class="card" style="margin:0;padding:14px;border:1px solid #c3c4c7;background:#fff;border-radius:4px">
						<h2 style="margin:0 0 .3em;font-size:14px">
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $card['page'] ) ); ?>"><?php echo esc_html( $card['title'] ); ?></a>
						</h2>
						<p style="margin:.2em 0">
							<span style="color:<?php echo $card['on'] ? '#007017' : '#996800'; ?>;font-weight:600"><?php echo esc_html( $card['state'] ); ?></span>
							<?php if ( $card['note'] ) : ?>
								<span style="color:#666"> · <?php echo esc_html( $card['note'] ); ?></span>
							<?php endif; ?>
						</p>
						<?php $blocked = $by_module[ $card['key'] ]['blocked'] ?? 0; ?>
						<?php $logged = $by_module[ $card['key'] ]['logged'] ?? 0; ?>
						<p style="margin:.2em 0;color:#666;font-size:12px">
							7 days: <?php echo esc_html( number_format_i18n( $blocked ) ); ?> blocked,
							<?php echo esc_html( number_format_i18n( $logged ) ); ?> logged
						</p>
					</div>
				<?php endforeach; ?>
			</div>

			<h2>Recent events</h2>
			<?php if ( empty( $recent ) ) : ?>
				<p>No events recorded yet.</p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr><th style="width:140px">Time</th><th style="width:110px">Module</th><th style="width:160px">Event</th><th style="width:70px">Action</th><th style="width:120px">IP</th><th>Detail</th></tr></thead>
					<tbody>
					<?php foreach ( $recent as $row ) : ?>
						<tr>
							<td><?php echo esc_html( $row->created_at ); ?></td>
							<td><?php echo esc_html( $row->module ); ?></td>
							<td><code><?php echo esc_html( $row->event ); ?></code></td>
							<td><?php echo 'blocked' === $row->action ? '<span style="color:#b32d2e;font-weight:600">blocked</span>' : esc_html( $row->action ); ?></td>
							<td><?php echo esc_html( $row->ip ); ?></td>
							<td><?php echo esc_html( $row->detail ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-opsec-event-log' ) ); ?>">View full event log →</a></p>
			<?php endif; ?>
		</div>
		<?php
	}

	private static function integrity_note() {
		$last = get_option( 'wpopsec_integrity_last_result', array() );
		if ( empty( $last ) ) {
			return 'never scanned';
		}
		$issues = count( $last['core']['modified'] ?? array() ) + count( $last['core']['missing'] ?? array() )
			+ count( $last['diff']['added'] ?? array() ) + count( $last['diff']['modified'] ?? array() );
		return $issues ? sprintf( '%d change(s) flagged', $issues ) : 'no changes';
	}

	private static function watchdog_state() {
		$alerts = count( (array) get_option( 'wpopsec_user_watchdog_alerts', array() ) );
		return $alerts ? sprintf( '%d alert(s)', $alerts ) : 'Clear';
	}

	private static function hardening_note() {
		$hidden = get_option( 'wpopsec_hardening_hidden_result', array() );
		$n      = count( (array) ( $hidden['hidden'] ?? array() ) );
		if ( $n ) {
			return sprintf( '%d hidden plugin(s)', $n );
		}
		return class_exists( 'WPOpsec_Module_Hardening' ) && WPOpsec_Module_Hardening::uploads_guard_active()
			? 'uploads guarded'
			: 'uploads unguarded';
	}

	private static function vuln_note() {
		$last = get_option( 'wpopsec_vuln_last_result', array() );
		if ( empty( $last ) ) {
			return 'never scanned';
		}
		$n = count( $last['findings'] ?? array() );
		return $n ? sprintf( '%d flagged', $n ) : 'nothing flagged';
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
