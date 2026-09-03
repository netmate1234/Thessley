<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only log of verified good-bot visits — a separate table from the
 * main Event Log by design, not a filtered view of it: every row here is
 * written directly from wpopsec_ip_is_trusted() itself (mu-loader), at
 * the exact moment a request's IP matches a crawler-nets.conf section, not
 * from any check.php gating a request. It never blocks anything and has
 * no enforcement mode — this module only owns the table and the admin view.
 *
 * A verified match can never be blocked by anything else in this codebase
 * (every module checks exemption before ever deciding to block), so every
 * row is definitionally a pass. Whether a given IP was *also* blocked at
 * some other point — before it was whitelisted, or a different, unverified
 * IP spoofing the same bot's user-agent — is answered by cross-checking
 * the main Event Log at render time, not by anything tracked here.
 */
class WPOpsec_Module_Bot_Log {

	const CRON_HOOK      = 'wpopsec_bot_log_prune';
	const DB_VERSION     = 1;
	const PER_PAGE       = 50;
	const DEFAULT_RETAIN = 14; // days — shorter than the main Event Log's 30, since a single crawler can generate far more rows per day than actual security events do

	public static function activate() {
		self::install_table();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		// Table intentionally left in place, same reasoning as Event Log.
	}

	public static function register() {
		self::maybe_upgrade_table();

		add_action( self::CRON_HOOK, array( __CLASS__, 'prune' ) );
		add_action( 'admin_post_wpopsec_bl_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wpopsec_bl_clear', array( __CLASS__, 'handle_clear' ) );

		return __CLASS__;
	}

	public static function install_table() {
		global $wpdb;

		$table   = wpopsec_bot_log_table();
		$collate = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at datetime NOT NULL,
				bot_name varchar(128) NOT NULL DEFAULT '',
				ip varchar(45) NOT NULL DEFAULT '',
				uri varchar(255) NOT NULL DEFAULT '',
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY bot_name (bot_name),
				KEY ip (ip)
			) {$collate};"
		);

		update_option( 'wpopsec_bot_log_db_version', self::DB_VERSION, false );
	}

	private static function maybe_upgrade_table() {
		if ( (int) get_option( 'wpopsec_bot_log_db_version', 0 ) !== self::DB_VERSION ) {
			self::install_table();
		}
	}

	public static function prune() {
		global $wpdb;

		$days  = max( 1, (int) get_option( 'wpopsec_bot_log_retain_days', self::DEFAULT_RETAIN ) );
		$table = wpopsec_bot_log_table();

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days
			)
		);
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_bl_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$days = isset( $_POST['retain_days'] ) ? max( 1, (int) $_POST['retain_days'] ) : self::DEFAULT_RETAIN;
		update_option( 'wpopsec_bot_log_retain_days', $days );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_clear() {
		check_admin_referer( 'wpopsec_bl_clear' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		global $wpdb;
		$wpdb->query( 'TRUNCATE TABLE ' . wpopsec_bot_log_table() );

		wp_safe_redirect( add_query_arg( 'cleared', '1', wp_get_referer() ) );
		exit;
	}

	/** @return array{rows:array, total:int} */
	private static function query_sightings( $filters, $page ) {
		global $wpdb;

		$table  = wpopsec_bot_log_table();
		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $filters['bot_name'] ) ) {
			$where[]  = 'bot_name = %s';
			$params[] = $filters['bot_name'];
		}
		if ( ! empty( $filters['ip'] ) ) {
			$where[]  = 'ip LIKE %s';
			$params[] = '%' . $wpdb->esc_like( $filters['ip'] ) . '%';
		}

		$where_sql = implode( ' AND ', $where );

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		$total     = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );

		$offset   = ( $page - 1 ) * self::PER_PAGE;
		$rows_sql = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d";
		$rows     = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $params, array( self::PER_PAGE, $offset ) ) ) );

		return array( 'rows' => $rows ?: array(), 'total' => $total );
	}

	/**
	 * Which of these IPs also have a 'blocked' row in the main Event Log,
	 * at any time — one query for the whole displayed page rather than
	 * one per row. A hit here means either this IP got blocked before it
	 * was whitelisted, or a different request from the same IP tripped
	 * something despite being trusted overall (e.g. a signature match a
	 * trusted source shouldn't be exempt from) — either way, worth a look.
	 */
	private static function blocked_elsewhere( array $ips ) {
		global $wpdb;
		if ( empty( $ips ) ) {
			return array();
		}
		$ips  = array_unique( $ips );
		$in   = implode( ',', array_fill( 0, count( $ips ), '%s' ) );
		$rows = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT ip FROM " . wpopsec_events_table() . " WHERE action = 'blocked' AND ip IN ({$in})",
				$ips
			)
		);
		return array_flip( $rows ?: array() );
	}

	public static function render_page() {
		global $wpdb;

		$filters = array(
			'bot_name' => isset( $_GET['f_bot'] ) ? sanitize_text_field( wp_unslash( $_GET['f_bot'] ) ) : '',
			'ip'       => isset( $_GET['f_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['f_ip'] ) ) : '',
		);
		$page = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;

		$result = self::query_sightings( $filters, $page );
		$table  = wpopsec_bot_log_table();

		$bot_names = $wpdb->get_col( "SELECT DISTINCT bot_name FROM {$table} ORDER BY bot_name" ) ?: array();
		$retain    = (int) get_option( 'wpopsec_bot_log_retain_days', self::DEFAULT_RETAIN );

		$last24    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)" );
		$distinct24 = (int) $wpdb->get_var( "SELECT COUNT(DISTINCT bot_name) FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)" );
		$top_bot   = $wpdb->get_row( "SELECT bot_name, COUNT(*) c FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 DAY) GROUP BY bot_name ORDER BY c DESC LIMIT 1" );

		$row_ips        = wp_list_pluck( $result['rows'], 'ip' );
		$blocked_ip_set = self::blocked_elsewhere( $row_ips );

		WPOpsec_UI::open( 'bot-log' );

		if ( isset( $_GET['saved'] ) ) {
			WPOpsec_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['cleared'] ) ) {
			WPOpsec_UI::notice( 'success', 'Bot log cleared.' );
		}

		WPOpsec_UI::tiles(
			array(
				array( 'icon' => 'networking', 'tone' => 'quiet', 'value' => number_format_i18n( $result['total'] ), 'label' => 'sightings stored' ),
				array( 'icon' => 'clock', 'tone' => 'quiet', 'value' => number_format_i18n( $last24 ), 'label' => 'in the last 24h' ),
				array( 'icon' => 'admin-site', 'tone' => 'quiet', 'value' => number_format_i18n( $distinct24 ), 'label' => 'distinct bots · 24h' ),
				array(
					'icon'  => 'star-filled',
					'tone'  => 'quiet',
					'value' => $top_bot ? number_format_i18n( (int) $top_bot->c ) : '—',
					'label' => $top_bot ? 'busiest · ' . $top_bot->bot_name : 'nothing in 24h',
				),
			)
		);

		WPOpsec_UI::section( 'Sightings', 'networking', sprintf( '%s matching', number_format_i18n( $result['total'] ) ) );
		?>
		<form method="get" class="wpopsec-actions" style="margin-bottom:14px">
			<?php wp_parse_str( WPOpsec_Menu_Router::query( 'bot-log' ), $route ); ?>
			<?php foreach ( $route as $k => $v ) : ?>
				<input type="hidden" name="<?php echo esc_attr( $k ); ?>" value="<?php echo esc_attr( $v ); ?>">
			<?php endforeach; ?>
			<select name="f_bot">
				<option value="">All bots</option>
				<?php foreach ( $bot_names as $b ) : ?>
					<option value="<?php echo esc_attr( $b ); ?>" <?php selected( $filters['bot_name'], $b ); ?>><?php echo esc_html( $b ); ?></option>
				<?php endforeach; ?>
			</select>
			<input type="text" name="f_ip" value="<?php echo esc_attr( $filters['ip'] ); ?>" placeholder="Search IP" style="width:150px">
			<?php submit_button( 'Filter', 'secondary', 'submit', false ); ?>
		</form>

		<table class="wpopsec-table">
			<thead>
				<tr>
					<th style="width:130px">Time</th>
					<th>Bot</th>
					<th style="width:170px">IP</th>
					<th style="width:130px">Also blocked?</th>
					<th>Request</th>
				</tr>
			</thead>
			<tbody>
			<?php if ( empty( $result['rows'] ) ) : ?>
				<tr><td colspan="5"><div class="wpopsec-empty"><span class="dashicons dashicons-networking"></span><p>No bot visits recorded yet.</p></div></td></tr>
			<?php else : ?>
				<?php foreach ( $result['rows'] as $row ) : ?>
					<tr>
						<td class="wpopsec-nowrap"><?php echo esc_html( mysql2date( 'M j, H:i', $row->created_at ) ); ?></td>
						<td><?php echo esc_html( $row->bot_name ); ?></td>
						<td><code class="wpopsec-nowrap"><?php echo esc_html( $row->ip ); ?></code></td>
						<td>
							<?php if ( isset( $blocked_ip_set[ $row->ip ] ) ) : ?>
								<a href="<?php echo esc_url( WPOpsec_Menu_Router::url( 'event-log', array( 'f_ip' => $row->ip ) ) ); ?>">
									<?php WPOpsec_UI::badge( 'yes, elsewhere', 'bad' ); ?>
								</a>
							<?php else : ?>
								<?php WPOpsec_UI::badge( 'no', 'good' ); ?>
							<?php endif; ?>
						</td>
						<td class="wpopsec-muted"><code style="font-size:11px"><?php echo esc_html( $row->uri ); ?></code></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>

		<?php
		$total_pages = (int) ceil( $result['total'] / self::PER_PAGE );
		if ( $total_pages > 1 ) {
			echo '<div class="tablenav" style="margin-top:12px"><div class="tablenav-pages">';
			echo paginate_links(
				array(
					'base'    => add_query_arg( 'paged', '%#%' ),
					'format'  => '',
					'current' => $page,
					'total'   => $total_pages,
				)
			);
			echo '</div></div>';
		}

		WPOpsec_UI::section_end();
		?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wpopsec_bl_save_settings' ); ?>
			<input type="hidden" name="action" value="wpopsec_bl_save_settings">

			<?php WPOpsec_UI::section( 'Settings', 'admin-generic' ); ?>
				<?php
				WPOpsec_UI::row(
					'Retention',
					function () use ( $retain ) {
						?>
						Keep sightings for <input type="number" name="retain_days" value="<?php echo esc_attr( $retain ); ?>" min="1" style="width:6em"> days
						<?php
					},
					'A single crawler can generate far more rows per day than actual security events do, so this defaults shorter than the Event Log.'
				);
				?>
			<?php WPOpsec_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>

		<div class="wpopsec-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
				onsubmit="return confirm('Delete all recorded bot sightings? This cannot be undone.');">
				<?php wp_nonce_field( 'wpopsec_bl_clear' ); ?>
				<input type="hidden" name="action" value="wpopsec_bl_clear">
				<?php submit_button( 'Clear bot log', 'delete', 'submit', false ); ?>
			</form>
		</div>
		<?php
		WPOpsec_UI::close();
	}
}
