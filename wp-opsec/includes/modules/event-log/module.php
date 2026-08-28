<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Central event log. Owns the table every other module writes to via
 * wpopsec_log_event(), plus the admin view for reading it.
 */
class WPOpsec_Module_Event_Log {

	const CRON_HOOK      = 'wpopsec_event_log_prune';
	const DB_VERSION     = 1;
	const PER_PAGE       = 50;
	const DEFAULT_RETAIN = 30; // days

	public static function activate() {
		self::install_table();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		// Table is intentionally left in place — deactivating shouldn't
		// destroy the audit trail. Uninstall can drop it.
	}

	public static function register() {
		self::maybe_upgrade_table();

		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'prune' ) );
		add_action( 'admin_post_wpopsec_el_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wpopsec_el_clear', array( __CLASS__, 'handle_clear' ) );

		return __CLASS__;
	}

	public static function install_table() {
		global $wpdb;

		$table   = wpopsec_events_table();
		$collate = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at datetime NOT NULL,
				module varchar(32) NOT NULL DEFAULT '',
				event varchar(64) NOT NULL DEFAULT '',
				action varchar(16) NOT NULL DEFAULT '',
				ip varchar(45) NOT NULL DEFAULT '',
				uri varchar(255) NOT NULL DEFAULT '',
				detail text NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY module_event (module,event),
				KEY ip (ip)
			) {$collate};"
		);

		update_option( 'wpopsec_event_log_db_version', self::DB_VERSION, false );
	}

	private static function maybe_upgrade_table() {
		if ( (int) get_option( 'wpopsec_event_log_db_version', 0 ) !== self::DB_VERSION ) {
			self::install_table();
		}
	}

	public static function prune() {
		global $wpdb;

		$days = max( 1, (int) get_option( 'wpopsec_event_log_retain_days', self::DEFAULT_RETAIN ) );
		$table = wpopsec_events_table();

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days
			)
		);
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'Event Log',
			'Event Log',
			'manage_options',
			'wp-opsec-event-log',
			array( __CLASS__, 'render_page' )
		);
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_el_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$days = isset( $_POST['retain_days'] ) ? max( 1, (int) $_POST['retain_days'] ) : self::DEFAULT_RETAIN;
		update_option( 'wpopsec_event_log_retain_days', $days );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_clear() {
		check_admin_referer( 'wpopsec_el_clear' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		global $wpdb;
		$wpdb->query( 'TRUNCATE TABLE ' . wpopsec_events_table() );

		wp_safe_redirect( add_query_arg( 'cleared', '1', wp_get_referer() ) );
		exit;
	}

	/** @return array{rows:array, total:int} */
	private static function query_events( $filters, $page ) {
		global $wpdb;

		$table  = wpopsec_events_table();
		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $filters['module'] ) ) {
			$where[]  = 'module = %s';
			$params[] = $filters['module'];
		}
		if ( ! empty( $filters['action'] ) ) {
			$where[]  = 'action = %s';
			$params[] = $filters['action'];
		}
		if ( ! empty( $filters['ip'] ) ) {
			$where[]  = 'ip = %s';
			$params[] = $filters['ip'];
		}

		$where_sql = implode( ' AND ', $where );

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		$total     = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );

		$offset   = ( $page - 1 ) * self::PER_PAGE;
		$rows_sql = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d";
		$rows     = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $params, array( self::PER_PAGE, $offset ) ) ) );

		return array( 'rows' => $rows ?: array(), 'total' => $total );
	}

	public static function render_page() {
		global $wpdb;

		$filters = array(
			'module' => isset( $_GET['f_module'] ) ? sanitize_text_field( wp_unslash( $_GET['f_module'] ) ) : '',
			'action' => isset( $_GET['f_action'] ) ? sanitize_text_field( wp_unslash( $_GET['f_action'] ) ) : '',
			'ip'     => isset( $_GET['f_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['f_ip'] ) ) : '',
		);
		$page = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;

		$result = self::query_events( $filters, $page );
		$table  = wpopsec_events_table();

		$modules = $wpdb->get_col( "SELECT DISTINCT module FROM {$table} ORDER BY module" ) ?: array();
		$retain  = (int) get_option( 'wpopsec_event_log_retain_days', self::DEFAULT_RETAIN );

		$last24 = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)" );
		$blocked24 = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE action = 'blocked' AND created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)" );
		?>
		<div class="wrap">
			<h1>WP Opsec — Event Log</h1>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['cleared'] ) ) : ?>
				<div class="notice notice-success"><p>Event log cleared.</p></div>
			<?php endif; ?>

			<p>
				<strong><?php echo esc_html( number_format_i18n( $result['total'] ) ); ?></strong> events stored ·
				<strong><?php echo esc_html( number_format_i18n( $last24 ) ); ?></strong> in the last 24h
				(<?php echo esc_html( number_format_i18n( $blocked24 ) ); ?> blocked).
			</p>

			<form method="get" style="margin:1em 0">
				<input type="hidden" name="page" value="wp-opsec-event-log">
				<select name="f_module">
					<option value="">All modules</option>
					<?php foreach ( $modules as $m ) : ?>
						<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $filters['module'], $m ); ?>><?php echo esc_html( $m ); ?></option>
					<?php endforeach; ?>
				</select>
				<select name="f_action">
					<option value="">Any action</option>
					<?php foreach ( array( 'blocked', 'logged', 'noted' ) as $a ) : ?>
						<option value="<?php echo esc_attr( $a ); ?>" <?php selected( $filters['action'], $a ); ?>><?php echo esc_html( $a ); ?></option>
					<?php endforeach; ?>
				</select>
				<input type="text" name="f_ip" value="<?php echo esc_attr( $filters['ip'] ); ?>" placeholder="IP">
				<?php submit_button( 'Filter', 'secondary', 'submit', false ); ?>
			</form>

			<table class="widefat striped">
				<thead>
					<tr>
						<th style="width:140px">Time</th>
						<th style="width:100px">Module</th>
						<th style="width:160px">Event</th>
						<th style="width:70px">Action</th>
						<th style="width:120px">IP</th>
						<th>Request / detail</th>
					</tr>
				</thead>
				<tbody>
				<?php if ( empty( $result['rows'] ) ) : ?>
					<tr><td colspan="6">No events recorded.</td></tr>
				<?php else : ?>
					<?php foreach ( $result['rows'] as $row ) : ?>
						<tr>
							<td><?php echo esc_html( $row->created_at ); ?></td>
							<td><?php echo esc_html( $row->module ); ?></td>
							<td><code><?php echo esc_html( $row->event ); ?></code></td>
							<td>
								<?php if ( 'blocked' === $row->action ) : ?>
									<span style="color:#b32d2e;font-weight:600">blocked</span>
								<?php else : ?>
									<?php echo esc_html( $row->action ); ?>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( $row->ip ); ?></td>
							<td>
								<?php if ( $row->uri ) : ?>
									<code style="font-size:11px"><?php echo esc_html( $row->uri ); ?></code><br>
								<?php endif; ?>
								<?php echo esc_html( $row->detail ); ?>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>

			<?php
			$total_pages = (int) ceil( $result['total'] / self::PER_PAGE );
			if ( $total_pages > 1 ) :
				echo '<div class="tablenav"><div class="tablenav-pages">';
				echo paginate_links(
					array(
						'base'    => add_query_arg( 'paged', '%#%' ),
						'format'  => '',
						'current' => $page,
						'total'   => $total_pages,
					)
				);
				echo '</div></div>';
			endif;
			?>

			<h2>Settings</h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_el_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_el_save_settings">
				<table class="form-table">
					<tr>
						<th><label for="wpopsec_retain">Keep events for</label></th>
						<td>
							<input type="number" id="wpopsec_retain" name="retain_days" value="<?php echo esc_attr( $retain ); ?>" min="1" style="width:6em"> days
							<p class="description">Older events are deleted daily.</p>
						</td>
					</tr>
				</table>
				<?php submit_button( 'Save settings' ); ?>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
				onsubmit="return confirm('Delete all recorded events? This cannot be undone.');">
				<?php wp_nonce_field( 'wpopsec_el_clear' ); ?>
				<input type="hidden" name="action" value="wpopsec_el_clear">
				<?php submit_button( 'Clear event log', 'delete', 'submit', false ); ?>
			</form>
		</div>
		<?php
	}
}
