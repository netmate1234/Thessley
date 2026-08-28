<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Post-compromise containment.
 *
 * These settings don't stop the initial break-in — they remove the tools an
 * attacker reaches for immediately afterwards: editing PHP from the
 * dashboard, dropping a webshell into uploads, and hiding a malicious plugin
 * from the plugin list (which is what the 2026 supply-chain backdoors did).
 */
class WPOpsec_Module_Hardening {

	const CRON_HOOK = 'wpopsec_hardening_scan';

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 20 * MINUTE_IN_SECONDS ), 'twicedaily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		self::remove_uploads_guard();
	}

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_post_wpopsec_hd_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wpopsec_hd_scan_now', array( __CLASS__, 'handle_scan_now' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'scan_hidden_plugins' ) );

		if ( get_option( 'wpopsec_hardening_disable_file_edit', true ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		return __CLASS__;
	}

	private static function uploads_htaccess_path() {
		$uploads = wp_get_upload_dir();
		return trailingslashit( $uploads['basedir'] ) . '.htaccess';
	}

	const UPLOADS_GUARD_MARKER = '# BEGIN WP Opsec uploads guard';

	/**
	 * Blocks PHP execution inside wp-content/uploads. Any attacker who gets
	 * an arbitrary-file-upload primitive lands here first, and a .php file
	 * that can't execute is inert.
	 *
	 * Apache-only: nginx ignores .htaccess entirely, so on nginx this has to
	 * be a server-block rule instead, and the UI says so rather than
	 * pretending it worked.
	 */
	public static function write_uploads_guard() {
		$path = self::uploads_htaccess_path();

		$rules = self::UPLOADS_GUARD_MARKER . "\n"
			. "<FilesMatch \"\\.(?i:php|phtml|phps|phar|php[0-9]?)$\">\n"
			. "\tRequire all denied\n"
			. "</FilesMatch>\n"
			. "# END WP Opsec uploads guard\n";

		$existing = file_exists( $path ) ? (string) file_get_contents( $path ) : '';

		if ( false !== strpos( $existing, self::UPLOADS_GUARD_MARKER ) ) {
			return true; // already present
		}

		return false !== file_put_contents( $path, $rules . $existing, LOCK_EX );
	}

	public static function remove_uploads_guard() {
		$path = self::uploads_htaccess_path();
		if ( ! file_exists( $path ) ) {
			return;
		}

		$content = (string) file_get_contents( $path );
		$cleaned = preg_replace(
			'/' . preg_quote( self::UPLOADS_GUARD_MARKER, '/' ) . '.*?# END WP Opsec uploads guard\s*/s',
			'',
			$content
		);

		if ( '' === trim( (string) $cleaned ) ) {
			unlink( $path );
		} elseif ( $cleaned !== $content ) {
			file_put_contents( $path, $cleaned, LOCK_EX );
		}
	}

	public static function uploads_guard_active() {
		$path = self::uploads_htaccess_path();
		return file_exists( $path ) && false !== strpos( (string) file_get_contents( $path ), self::UPLOADS_GUARD_MARKER );
	}

	private static function is_apache() {
		return function_exists( 'apache_get_modules' ) || false !== stripos( (string) ( $_SERVER['SERVER_SOFTWARE'] ?? '' ), 'apache' );
	}

	/**
	 * Finds plugins that don't show up where an admin would look for them.
	 *
	 * A malicious plugin hides by filtering `all_plugins`, which is what the
	 * Plugins screen renders from. Note that get_plugins() does *not* run that
	 * filter, so comparing disk against get_plugins() would miss the trick
	 * entirely — the comparison has to be against the filtered list, i.e.
	 * what the admin actually sees.
	 *
	 * Both comparisons are kept: disk-vs-filtered catches the `all_plugins`
	 * trick, and disk-vs-get_plugins() catches a file whose header WordPress
	 * fails to parse at all.
	 */
	public static function scan_hidden_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$raw      = get_plugins();
		$shown    = (array) apply_filters( 'all_plugins', $raw );
		$reported = array_keys( $shown );
		$on_disk  = array();

		$dir = WP_PLUGIN_DIR;
		foreach ( (array) glob( $dir . '/*' ) as $entry ) {
			if ( is_dir( $entry ) ) {
				foreach ( (array) glob( $entry . '/*.php' ) as $php ) {
					if ( self::has_plugin_header( $php ) ) {
						$on_disk[] = basename( $entry ) . '/' . basename( $php );
					}
				}
			} elseif ( '.php' === substr( $entry, -4 ) && self::has_plugin_header( $entry ) ) {
				$on_disk[] = basename( $entry );
			}
		}

		$hidden = array_values( array_diff( $on_disk, $reported ) );

		// A plugin filtering itself out of the list it doesn't otherwise
		// belong out of is worth naming explicitly, since it's deliberate
		// concealment rather than a parsing quirk.
		$filtered_out = array_values( array_diff( array_keys( $raw ), $reported ) );
		foreach ( $filtered_out as $f ) {
			if ( ! in_array( $f, $hidden, true ) ) {
				$hidden[] = $f;
			}
		}

		// mu-plugins never appear in the normal plugin list and are a classic
		// persistence spot, so surface them for eyeballing rather than as a
		// finding — this plugin legitimately installs one itself.
		$mu = array();
		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			foreach ( (array) glob( WPMU_PLUGIN_DIR . '/*.php' ) as $php ) {
				$mu[] = basename( $php );
			}
		}

		$result = array( 'at' => time(), 'hidden' => $hidden, 'mu_plugins' => $mu );
		update_option( 'wpopsec_hardening_hidden_result', $result, false );

		if ( $hidden ) {
			wpopsec_log_event(
				'hardening',
				'hidden_plugin',
				'noted',
				sprintf( '%d plugin file(s) on disk but absent from the plugin list: %s', count( $hidden ), implode( ', ', array_slice( $hidden, 0, 5 ) ) )
			);
		}

		return $result;
	}

	private static function has_plugin_header( $file ) {
		$data = @file_get_contents( $file, false, null, 0, 8192 );
		return $data && preg_match( '/^[ \t\/*#@]*Plugin Name:/mi', $data );
	}

	public static function handle_scan_now() {
		check_admin_referer( 'wpopsec_hd_scan_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::scan_hidden_plugins();
		wp_safe_redirect( add_query_arg( 'scanned', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_hd_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'wpopsec_hardening_disable_file_edit', isset( $_POST['disable_file_edit'] ) );

		$want_guard = isset( $_POST['uploads_guard'] );
		update_option( 'wpopsec_hardening_uploads_guard', $want_guard );

		$notice = '1';
		if ( $want_guard ) {
			if ( ! self::write_uploads_guard() ) {
				$notice = 'guardfail';
			}
		} else {
			self::remove_uploads_guard();
		}

		wp_safe_redirect( add_query_arg( 'saved', $notice, wp_get_referer() ) );
		exit;
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'Hardening',
			'Hardening',
			'manage_options',
			'wp-opsec-hardening',
			array( __CLASS__, 'render_page' )
		);
	}

	public static function render_page() {
		$hidden_result = get_option( 'wpopsec_hardening_hidden_result', array() );
		$guard_active  = self::uploads_guard_active();
		$file_edit_off = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		?>
		<div class="wrap">
			<h1>WP Opsec — Hardening</h1>
			<p>Removes the tools an attacker uses <em>after</em> getting in: editing PHP from the dashboard, executing an uploaded webshell, and hiding a malicious plugin from the plugin list.</p>

			<?php if ( isset( $_GET['saved'] ) && '1' === $_GET['saved'] ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php elseif ( isset( $_GET['saved'] ) && 'guardfail' === $_GET['saved'] ) : ?>
				<div class="notice notice-error"><p>Couldn't write <code><?php echo esc_html( self::uploads_htaccess_path() ); ?></code> — check filesystem permissions.</p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['scanned'] ) ) : ?>
				<div class="notice notice-success"><p>Scan complete.</p></div>
			<?php endif; ?>

			<h2>Hidden plugins</h2>
			<p class="description">Files with a plugin header that exist on disk but don't appear in WordPress's plugin list. A backdoor can filter itself out of that list while staying active — comparing against the raw directory catches it.</p>
			<?php if ( empty( $hidden_result ) ) : ?>
				<p>Not scanned yet.</p>
			<?php elseif ( empty( $hidden_result['hidden'] ) ) : ?>
				<p style="color:#007017;font-weight:600">No hidden plugins found.</p>
			<?php else : ?>
				<div class="notice notice-error inline">
					<p><strong>Plugin files not shown in the plugin list:</strong></p>
					<ul style="margin-left:1.5em;list-style:disc">
						<?php foreach ( $hidden_result['hidden'] as $h ) : ?>
							<li><code><?php echo esc_html( $h ); ?></code></li>
						<?php endforeach; ?>
					</ul>
					<p>Inspect these on disk before deleting — note the file, then check its contents.</p>
				</div>
			<?php endif; ?>

			<?php if ( ! empty( $hidden_result['mu_plugins'] ) ) : ?>
				<p><strong>Must-use plugins</strong> (always active, never listed on the Plugins screen):</p>
				<ul style="margin-left:1.5em;list-style:disc">
					<?php foreach ( $hidden_result['mu_plugins'] as $mu ) : ?>
						<li><code><?php echo esc_html( $mu ); ?></code><?php echo 'wp-opsec-early.php' === $mu ? ' <em>— installed by this plugin</em>' : ''; ?></li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:1em 0">
				<?php wp_nonce_field( 'wpopsec_hd_scan_now' ); ?>
				<input type="hidden" name="action" value="wpopsec_hd_scan_now">
				<?php submit_button( 'Scan now', 'secondary', 'submit', false ); ?>
			</form>

			<h2>Settings</h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_hd_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_hd_save_settings">

				<table class="form-table">
					<tr>
						<th>Dashboard file editor</th>
						<td>
							<label><input type="checkbox" name="disable_file_edit" <?php checked( get_option( 'wpopsec_hardening_disable_file_edit', true ) ); ?>> Disable the plugin/theme code editor</label>
							<p class="description">
								Currently <strong><?php echo $file_edit_off ? 'disabled' : 'enabled'; ?></strong>.
								Anyone who reaches wp-admin as an administrator can otherwise edit PHP straight into a live file — the shortest path from stolen password to running code.
								<?php if ( defined( 'DISALLOW_FILE_EDIT' ) && ! get_option( 'wpopsec_hardening_disable_file_edit', true ) ) : ?>
									<br><em>Already set in wp-config.php, so unchecking this here has no effect.</em>
								<?php endif; ?>
							</p>
						</td>
					</tr>
					<tr>
						<th>PHP execution in uploads</th>
						<td>
							<label><input type="checkbox" name="uploads_guard" <?php checked( get_option( 'wpopsec_hardening_uploads_guard', false ) ); ?>> Block PHP execution in <code>wp-content/uploads</code></label>
							<p class="description">
								Currently <strong><?php echo $guard_active ? 'active' : 'not active'; ?></strong>
								(writes an <code>.htaccess</code> into the uploads folder).
								<?php if ( ! self::is_apache() ) : ?>
									<br><strong>This server doesn't look like Apache.</strong> nginx ignores <code>.htaccess</code>, so this needs an equivalent server-block rule instead:
									<code style="display:block;margin-top:.4em">location ~* /wp-content/uploads/.*\.php$ { deny all; }</code>
								<?php endif; ?>
							</p>
						</td>
					</tr>
				</table>

				<?php submit_button( 'Save settings' ); ?>
			</form>
		</div>
		<?php
	}
}
