<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Brute-force protection for wp-login.php and the XML-RPC login surface.
 *
 * Runs on normal WP hooks rather than the early gate: authentication
 * results only exist once WP has bootstrapped. The *enforcement* still
 * happens early, because a lockout escalates the IP into the shared local
 * blocklist, which the early gate reads on the next request.
 */
class WPOpsec_Module_Login_Guard {

	const CRON_HOOK = 'wpopsec_login_guard_prune';

	const DEFAULT_MAX_FAILS   = 8;
	const DEFAULT_WINDOW_MIN  = 15;
	const DEFAULT_LOCKOUT_MIN = 60;

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'hourly', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_post_wpopsec_lg_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'prune' ) );

		if ( get_option( 'wpopsec_login_guard_enabled', true ) ) {
			add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ) );
			add_action( 'wp_login', array( __CLASS__, 'on_login_success' ), 10, 2 );
			add_filter( 'authenticate', array( __CLASS__, 'maybe_block_login' ), 30, 3 );

			if ( get_option( 'wpopsec_login_guard_generic_errors', true ) ) {
				add_filter( 'login_errors', array( __CLASS__, 'genericize_errors' ) );
			}
		}

		return __CLASS__;
	}

	/**
	 * Per-IP state lives in its own transient rather than one shared option.
	 *
	 * A distributed credential-stuffing run touches a huge number of source
	 * IPs, and a single option meant every failed login unserialised,
	 * appended to and rewrote the entire structure — the attack made itself
	 * progressively more expensive to defend against. Transients also expire
	 * on their own, so lockouts release without depending on cron.
	 */
	private static function entry_key( $ip ) {
		return 'wpopsec_lg_' . md5( $ip );
	}

	private static function get_entry( $ip ) {
		$entry = get_transient( self::entry_key( $ip ) );
		return is_array( $entry ) ? $entry : array( 'fails' => array(), 'locked_until' => 0 );
	}

	private static function save_entry( $ip, $entry ) {
		$window  = max( 1, (int) get_option( 'wpopsec_login_guard_window_min', self::DEFAULT_WINDOW_MIN ) ) * MINUTE_IN_SECONDS;
		$expires = max( $window, (int) ( $entry['locked_until'] ?? 0 ) - time() );

		set_transient( self::entry_key( $ip ), $entry, $expires );
		self::remember_ip( $ip );
	}

	private static function clear_entry( $ip ) {
		delete_transient( self::entry_key( $ip ) );
		self::forget_ip( $ip );
	}

	/**
	 * Small index of currently-locked IPs, purely so the admin screen can
	 * list them — transients aren't enumerable. Only locked IPs go in here,
	 * not every IP that ever failed a login, so it stays bounded.
	 */
	private static function remember_ip( $ip ) {
		$entry = self::get_entry( $ip );
		if ( empty( $entry['locked_until'] ) || $entry['locked_until'] < time() ) {
			return;
		}

		$index = (array) get_option( 'wpopsec_login_guard_locked', array() );
		$index[ $ip ] = (int) $entry['locked_until'];

		// Hard cap: under a very wide attack this list is for display only,
		// and enforcement never reads it — so dropping the oldest is safe.
		if ( count( $index ) > 500 ) {
			asort( $index );
			$index = array_slice( $index, -500, null, true );
		}

		update_option( 'wpopsec_login_guard_locked', $index, false );
	}

	private static function forget_ip( $ip ) {
		$index = (array) get_option( 'wpopsec_login_guard_locked', array() );
		if ( isset( $index[ $ip ] ) ) {
			unset( $index[ $ip ] );
			update_option( 'wpopsec_login_guard_locked', $index, false );
		}
	}

	/** @return array<string,int> ip => locked_until, expired entries dropped */
	private static function locked_ips() {
		$index   = (array) get_option( 'wpopsec_login_guard_locked', array() );
		$now     = time();
		$active  = array_filter(
			$index,
			function ( $until ) use ( $now ) {
				return (int) $until > $now;
			}
		);

		if ( count( $active ) !== count( $index ) ) {
			update_option( 'wpopsec_login_guard_locked', $active, false );
		}

		return $active;
	}

	public static function on_login_failed( $username ) {
		$ip = wpopsec_client_ip();
		if ( '' === $ip ) {
			return;
		}

		// Exempt IPs are never enforced against, so don't accumulate state
		// for them — it would show up as a phantom "locked out" row that
		// never actually blocks anything.
		if ( wpopsec_ip_is_exempt( $ip ) ) {
			return;
		}

		$window = max( 1, (int) get_option( 'wpopsec_login_guard_window_min', self::DEFAULT_WINDOW_MIN ) ) * MINUTE_IN_SECONDS;
		$max    = max( 1, (int) get_option( 'wpopsec_login_guard_max_fails', self::DEFAULT_MAX_FAILS ) );
		$now    = time();

		$entry = self::get_entry( $ip );

		// Keep only failures inside the rolling window.
		$entry['fails'] = array_values(
			array_filter(
				$entry['fails'],
				function ( $ts ) use ( $now, $window ) {
					return $ts > $now - $window;
				}
			)
		);
		$entry['fails'][] = $now;

		$count = count( $entry['fails'] );

		if ( $count >= $max ) {
			$lockout = max( 1, (int) get_option( 'wpopsec_login_guard_lockout_min', self::DEFAULT_LOCKOUT_MIN ) );
			$entry['locked_until'] = $now + ( $lockout * MINUTE_IN_SECONDS );
			$entry['fails']        = array();

			self::save_entry( $ip, $entry );

			wpopsec_log_event(
				'login-guard',
				'lockout',
				'blocked',
				sprintf( '%d failed logins in %d min; locked %d min; last user "%s"', $count, (int) get_option( 'wpopsec_login_guard_window_min', self::DEFAULT_WINDOW_MIN ), $lockout, $username )
			);

			// Escalate to the shared local blocklist so the early gate stops
			// this IP before WP even bootstraps on subsequent requests.
			if ( get_option( 'wpopsec_login_guard_escalate', true ) ) {
				wpopsec_local_blocklist_add( $ip, 'login-guard: brute force', $lockout * MINUTE_IN_SECONDS );
			}
			return;
		}

		self::save_entry( $ip, $entry );

		wpopsec_log_event( 'login-guard', 'login_failed', 'noted', sprintf( 'attempt %d/%d for user "%s"', $count, $max, $username ) );
	}

	public static function on_login_success( $user_login, $user = null ) {
		$ip = wpopsec_client_ip();
		if ( '' === $ip ) {
			return;
		}

		// A successful login clears the counter for that IP — otherwise a
		// user who fat-fingers their password a few times, then gets in,
		// stays one typo away from a lockout for the rest of the window.
		self::clear_entry( $ip );

		wpopsec_log_event( 'login-guard', 'login_success', 'noted', sprintf( 'user "%s"', $user_login ) );
	}

	/**
	 * @param WP_User|WP_Error|null $user
	 * @return WP_User|WP_Error|null
	 */
	public static function maybe_block_login( $user, $username, $password ) {
		// Nothing to do for an empty submit (the login form's own first load).
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$ip = wpopsec_client_ip();
		if ( '' === $ip || wpopsec_ip_is_exempt( $ip ) ) {
			return $user; // LAN/dev/trusted crawler ranges are never locked out
		}

		$entry = self::get_entry( $ip );
		$until = (int) ( $entry['locked_until'] ?? 0 );

		if ( $until > time() ) {
			$minutes = max( 1, (int) ceil( ( $until - time() ) / MINUTE_IN_SECONDS ) );

			wpopsec_log_event( 'login-guard', 'locked_attempt', 'blocked', sprintf( 'attempt while locked; %d min remaining', $minutes ) );

			return new WP_Error(
				'wpopsec_locked_out',
				sprintf(
					/* translators: %d: minutes remaining */
					__( '<strong>Too many failed login attempts.</strong> Try again in %d minutes.', 'wp-opsec' ),
					$minutes
				)
			);
		}

		return $user;
	}

	/**
	 * WP's default login errors distinguish "unknown username" from "wrong
	 * password", which confirms which accounts exist. Collapse to one
	 * message so a brute-forcer can't enumerate valid users for free.
	 */
	public static function genericize_errors( $error ) {
		// Don't mask our own lockout message — the user needs to know why.
		if ( is_string( $error ) && false !== strpos( $error, 'Too many failed login attempts' ) ) {
			return $error;
		}
		return __( '<strong>Error:</strong> Invalid username, email address or password.', 'wp-opsec' );
	}

	/**
	 * Per-IP state expires with its own transient now, so this only tidies
	 * the display index of locked IPs. Kept on cron so the list doesn't
	 * accumulate entries on a site nobody visits in wp-admin.
	 */
	public static function prune() {
		self::locked_ips();
	}

	/** Clears every lockout — used by the "clear all" maintenance toggle. */
	private static function clear_all_lockouts() {
		foreach ( array_keys( self::locked_ips() ) as $ip ) {
			delete_transient( self::entry_key( $ip ) );
		}
		update_option( 'wpopsec_login_guard_locked', array(), false );
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'Login Guard',
			'Login Guard',
			'manage_options',
			'wp-opsec-login-guard',
			array( __CLASS__, 'render_settings_page' )
		);
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_lg_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'wpopsec_login_guard_enabled', isset( $_POST['enabled'] ) );
		update_option( 'wpopsec_login_guard_escalate', isset( $_POST['escalate'] ) );
		update_option( 'wpopsec_login_guard_generic_errors', isset( $_POST['generic_errors'] ) );
		update_option( 'wpopsec_login_guard_max_fails', max( 1, (int) ( $_POST['max_fails'] ?? self::DEFAULT_MAX_FAILS ) ) );
		update_option( 'wpopsec_login_guard_window_min', max( 1, (int) ( $_POST['window_min'] ?? self::DEFAULT_WINDOW_MIN ) ) );
		update_option( 'wpopsec_login_guard_lockout_min', max( 1, (int) ( $_POST['lockout_min'] ?? self::DEFAULT_LOCKOUT_MIN ) ) );

		if ( isset( $_POST['clear_lockouts'] ) ) {
			self::clear_all_lockouts();
		}

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$enabled     = get_option( 'wpopsec_login_guard_enabled', true );
		$escalate    = get_option( 'wpopsec_login_guard_escalate', true );
		$generic     = get_option( 'wpopsec_login_guard_generic_errors', true );
		$max_fails   = (int) get_option( 'wpopsec_login_guard_max_fails', self::DEFAULT_MAX_FAILS );
		$window_min  = (int) get_option( 'wpopsec_login_guard_window_min', self::DEFAULT_WINDOW_MIN );
		$lockout_min = (int) get_option( 'wpopsec_login_guard_lockout_min', self::DEFAULT_LOCKOUT_MIN );

		$locked = self::locked_ips();
		arsort( $locked );
		?>
		<div class="wrap">
			<h1>WP Opsec — Login Guard</h1>
			<p>Rate-limits failed logins per IP and locks out brute-force attempts. Your LAN, and anything in the trusted networks file, is never locked out.</p>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>

			<h2>Currently locked out</h2>
			<?php if ( empty( $locked ) ) : ?>
				<p>No IPs are locked out.</p>
			<?php else : ?>
				<table class="widefat" style="max-width:500px">
					<thead><tr><th>IP</th><th>Locked until</th></tr></thead>
					<tbody>
					<?php foreach ( $locked as $ip => $until ) : ?>
						<tr>
							<td><?php echo esc_html( $ip ); ?></td>
							<td><?php echo esc_html( date_i18n( 'Y-m-d H:i', (int) $until ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_lg_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_lg_save_settings">

				<table class="form-table">
					<tr>
						<th>Enabled</th>
						<td><label><input type="checkbox" name="enabled" <?php checked( $enabled ); ?>> Rate-limit failed logins</label></td>
					</tr>
					<tr>
						<th>Threshold</th>
						<td>
							<input type="number" name="max_fails" value="<?php echo esc_attr( $max_fails ); ?>" min="1" style="width:5em">
							failures within
							<input type="number" name="window_min" value="<?php echo esc_attr( $window_min ); ?>" min="1" style="width:5em">
							minutes
							<p class="description">A successful login clears the counter for that IP.</p>
						</td>
					</tr>
					<tr>
						<th>Lockout length</th>
						<td>
							<input type="number" name="lockout_min" value="<?php echo esc_attr( $lockout_min ); ?>" min="1" style="width:5em"> minutes
						</td>
					</tr>
					<tr>
						<th>On lockout</th>
						<td>
							<label><input type="checkbox" name="escalate" <?php checked( $escalate ); ?>> Also add the IP to the local blocklist</label>
							<p class="description">Blocks them at the early gate for the lockout duration, before WordPress loads — cheaper than serving the login page to a bot.</p>
						</td>
					</tr>
					<tr>
						<th>Login errors</th>
						<td>
							<label><input type="checkbox" name="generic_errors" <?php checked( $generic ); ?>> Use a generic "invalid credentials" message</label>
							<p class="description">WordPress by default says whether the <em>username</em> exists, which confirms valid accounts to an attacker.</p>
						</td>
					</tr>
					<tr>
						<th>Maintenance</th>
						<td><label><input type="checkbox" name="clear_lockouts"> Clear all current lockouts on save</label></td>
					</tr>
				</table>

				<?php submit_button( 'Save settings' ); ?>
			</form>
		</div>
		<?php
	}
}
