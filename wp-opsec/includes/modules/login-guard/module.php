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

	private static function state() {
		return get_option( 'wpopsec_login_guard_state', array() );
	}

	private static function save_state( $state ) {
		update_option( 'wpopsec_login_guard_state', $state, false );
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

		$state = self::state();
		$entry = $state[ $ip ] ?? array( 'fails' => array(), 'locked_until' => 0 );

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

			$state[ $ip ] = $entry;
			self::save_state( $state );

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

		$state[ $ip ] = $entry;
		self::save_state( $state );

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
		$state = self::state();
		if ( isset( $state[ $ip ] ) ) {
			unset( $state[ $ip ] );
			self::save_state( $state );
		}

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

		$state = self::state();
		$until = (int) ( $state[ $ip ]['locked_until'] ?? 0 );

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

	public static function prune() {
		$state = self::state();
		$now   = time();
		$window = max( 1, (int) get_option( 'wpopsec_login_guard_window_min', self::DEFAULT_WINDOW_MIN ) ) * MINUTE_IN_SECONDS;

		foreach ( $state as $ip => $entry ) {
			$locked = (int) ( $entry['locked_until'] ?? 0 ) > $now;
			$recent = false;
			foreach ( (array) ( $entry['fails'] ?? array() ) as $ts ) {
				if ( $ts > $now - $window ) {
					$recent = true;
					break;
				}
			}
			if ( ! $locked && ! $recent ) {
				unset( $state[ $ip ] );
			}
		}

		self::save_state( $state );
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
			self::save_state( array() );
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

		$state = self::state();
		$now   = time();
		$locked = array_filter(
			$state,
			function ( $e ) use ( $now ) {
				return (int) ( $e['locked_until'] ?? 0 ) > $now;
			}
		);
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
					<?php foreach ( $locked as $ip => $entry ) : ?>
						<tr>
							<td><?php echo esc_html( $ip ); ?></td>
							<td><?php echo esc_html( date( 'Y-m-d H:i', (int) $entry['locked_until'] ) ); ?></td>
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
