<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Automatic updates.
 *
 * Roughly 60% of WordPress infections exploit a vulnerability that already
 * had a patch, and heavily-targeted flaws reach mass exploitation in hours.
 * Reporting an available update (which vuln-scanner does) loses that race
 * if a human has to read the report first — so this closes the loop and
 * installs them.
 *
 * The "auto-update anything vuln-scanner flagged" mode is deliberately
 * separate from blanket auto-updates: some sites can't take unattended
 * feature updates, but almost every site wants the security ones.
 */
class WPOpsec_Module_Auto_Update {

	const CRON_HOOK = 'wpopsec_auto_update_sweep';

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 30 * MINUTE_IN_SECONDS ), 'twicedaily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( 'admin_post_wpopsec_au_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'sweep' ) );

		add_filter( 'allow_major_auto_core_updates', array( __CLASS__, 'allow_major_core' ), 20 );
		add_filter( 'allow_minor_auto_core_updates', array( __CLASS__, 'allow_minor_core' ), 20 );
		add_filter( 'auto_update_plugin', array( __CLASS__, 'filter_plugin' ), 20, 2 );
		add_filter( 'auto_update_theme', array( __CLASS__, 'filter_theme' ), 20, 2 );

		// Record what WordPress actually did, so the event log shows a real
		// audit trail rather than just "an update happened at some point".
		add_action( 'automatic_updates_complete', array( __CLASS__, 'log_results' ) );

		return __CLASS__;
	}

	public static function allow_minor_core( $enabled ) {
		$mode = get_option( 'wpopsec_auto_update_core', 'minor' );
		return in_array( $mode, array( 'minor', 'major' ), true ) ? true : $enabled;
	}

	public static function allow_major_core( $enabled ) {
		$mode = get_option( 'wpopsec_auto_update_core', 'minor' );
		if ( 'major' === $mode ) {
			return true;
		}
		if ( 'off' === $mode ) {
			return false;
		}
		return $enabled;
	}

	/**
	 * @param bool|null $update
	 * @param object    $item
	 */
	public static function filter_plugin( $update, $item ) {
		$mode = get_option( 'wpopsec_auto_update_plugins', 'flagged' );
		$file = $item->plugin ?? '';

		if ( 'all' === $mode ) {
			return ! self::is_excluded( $file );
		}

		if ( 'flagged' === $mode ) {
			return self::is_flagged_by_scanner( $file ) && ! self::is_excluded( $file );
		}

		return $update; // 'off' — leave WordPress's own per-plugin setting alone
	}

	public static function filter_theme( $update, $item ) {
		$mode = get_option( 'wpopsec_auto_update_themes', 'off' );
		if ( 'all' === $mode ) {
			return true;
		}
		return $update;
	}

	private static function is_excluded( $plugin_file ) {
		$excluded = (array) get_option( 'wpopsec_auto_update_exclude', array() );
		return in_array( $plugin_file, $excluded, true );
	}

	/**
	 * True if vuln-scanner's last run flagged this plugin for something that
	 * an update would actually fix. "Unmaintained" is excluded on purpose:
	 * there's no newer release to install, so it can't be auto-resolved.
	 */
	private static function is_flagged_by_scanner( $plugin_file ) {
		$last = get_option( 'wpopsec_vuln_last_result', array() );
		if ( empty( $last['findings'] ) ) {
			return false;
		}

		foreach ( $last['findings'] as $f ) {
			if ( 'plugin' !== $f['type'] || $f['file'] !== $plugin_file ) {
				continue;
			}
			foreach ( $f['issues'] as $issue ) {
				if ( in_array( $issue['kind'], array( 'outdated', 'cve' ), true ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * WordPress only runs its auto-updater on its own schedule. Nudge it,
	 * after refreshing vuln-scanner data so "flagged" mode is deciding on
	 * current information rather than a stale scan.
	 */
	public static function sweep() {
		if ( 'off' === get_option( 'wpopsec_auto_update_plugins', 'flagged' )
			&& 'off' === get_option( 'wpopsec_auto_update_core', 'minor' )
			&& 'off' === get_option( 'wpopsec_auto_update_themes', 'off' ) ) {
			return;
		}

		if ( class_exists( 'WPOpsec_Module_Vuln_Scanner' ) && 'flagged' === get_option( 'wpopsec_auto_update_plugins', 'flagged' ) ) {
			WPOpsec_Module_Vuln_Scanner::run_scan();
		}

		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';

		wp_update_plugins();
		wp_update_themes();

		$upgrader = new WP_Automatic_Updater();
		if ( $upgrader->is_disabled() ) {
			wpopsec_log_event( 'auto-update', 'updater_disabled', 'noted', 'AUTOMATIC_UPDATER_DISABLED or DISALLOW_FILE_MODS is set' );
			return;
		}

		$upgrader->run();
	}

	public static function log_results( $results ) {
		foreach ( array( 'core', 'plugin', 'theme' ) as $type ) {
			if ( empty( $results[ $type ] ) ) {
				continue;
			}
			foreach ( $results[ $type ] as $item ) {
				$name    = $item->name ?? ( $item->item->slug ?? 'unknown' );
				$success = ! empty( $item->result ) && ! is_wp_error( $item->result );

				wpopsec_log_event(
					'auto-update',
					$success ? 'updated' : 'update_failed',
					'noted',
					sprintf( '%s: %s', $type, $name )
				);
			}
		}
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'Auto Updates',
			'Auto Updates',
			'manage_options',
			'wp-opsec-auto-update',
			array( __CLASS__, 'render_settings_page' )
		);
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_au_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$core = sanitize_text_field( wp_unslash( $_POST['core'] ?? 'minor' ) );
		update_option( 'wpopsec_auto_update_core', in_array( $core, array( 'off', 'minor', 'major' ), true ) ? $core : 'minor' );

		$plugins = sanitize_text_field( wp_unslash( $_POST['plugins'] ?? 'flagged' ) );
		update_option( 'wpopsec_auto_update_plugins', in_array( $plugins, array( 'off', 'flagged', 'all' ), true ) ? $plugins : 'flagged' );

		$themes = sanitize_text_field( wp_unslash( $_POST['themes'] ?? 'off' ) );
		update_option( 'wpopsec_auto_update_themes', in_array( $themes, array( 'off', 'all' ), true ) ? $themes : 'off' );

		$exclude = isset( $_POST['exclude'] ) ? (array) wp_unslash( $_POST['exclude'] ) : array();
		update_option( 'wpopsec_auto_update_exclude', array_map( 'sanitize_text_field', $exclude ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$core    = get_option( 'wpopsec_auto_update_core', 'minor' );
		$plugins = get_option( 'wpopsec_auto_update_plugins', 'flagged' );
		$themes  = get_option( 'wpopsec_auto_update_themes', 'off' );
		$exclude = (array) get_option( 'wpopsec_auto_update_exclude', array() );

		$scan       = get_option( 'wpopsec_vuln_last_result', array() );
		$flagged_ct = 0;
		foreach ( (array) ( $scan['findings'] ?? array() ) as $f ) {
			foreach ( $f['issues'] as $i ) {
				if ( in_array( $i['kind'], array( 'outdated', 'cve' ), true ) ) {
					$flagged_ct++;
					break;
				}
			}
		}

		$blocked = defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED;
		$no_mods = defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS;
		?>
		<div class="wrap">
			<h1>WP Opsec — Auto Updates</h1>
			<p>About 60% of WordPress compromises exploit a flaw that was <em>already patched</em>, and widely-targeted vulnerabilities get mass-exploited within hours of disclosure. Installing the update is the fix; reading a report about it later isn't.</p>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>

			<?php if ( $blocked || $no_mods ) : ?>
				<div class="notice notice-error inline">
					<p><strong>Automatic updates are disabled at the wp-config level</strong>
					(<?php echo esc_html( $blocked ? 'AUTOMATIC_UPDATER_DISABLED' : 'DISALLOW_FILE_MODS' ); ?>).
					Nothing on this page can take effect until that constant is removed.</p>
				</div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_au_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_au_save_settings">

				<table class="form-table">
					<tr>
						<th>WordPress core</th>
						<td>
							<label><input type="radio" name="core" value="minor" <?php checked( $core, 'minor' ); ?>> Security &amp; maintenance releases only <em>(recommended)</em></label><br>
							<label><input type="radio" name="core" value="major" <?php checked( $core, 'major' ); ?>> All releases, including major versions</label><br>
							<label><input type="radio" name="core" value="off" <?php checked( $core, 'off' ); ?>> Off</label>
							<p class="description">Minor releases are where core security fixes ship, and they're deliberately low-risk. Major releases can change editor behaviour.</p>
						</td>
					</tr>
					<tr>
						<th>Plugins</th>
						<td>
							<label><input type="radio" name="plugins" value="flagged" <?php checked( $plugins, 'flagged' ); ?>>
								Only plugins the vulnerability scan flagged <em>(recommended)</em>
								<?php if ( $scan ) : ?>
									— currently <strong><?php echo esc_html( $flagged_ct ); ?></strong>
								<?php endif; ?>
							</label><br>
							<label><input type="radio" name="plugins" value="all" <?php checked( $plugins, 'all' ); ?>> All plugins</label><br>
							<label><input type="radio" name="plugins" value="off" <?php checked( $plugins, 'off' ); ?>> Off (use WordPress's own per-plugin settings)</label>
							<p class="description">91% of WordPress vulnerabilities are in plugins, so this is the setting that matters most. "Flagged" re-runs the scan before each sweep so it acts on current data.</p>
						</td>
					</tr>
					<tr>
						<th>Themes</th>
						<td>
							<label><input type="radio" name="themes" value="all" <?php checked( $themes, 'all' ); ?>> All themes</label><br>
							<label><input type="radio" name="themes" value="off" <?php checked( $themes, 'off' ); ?>> Off</label>
							<p class="description">Leave off if you've customised a theme directly instead of using a child theme — an update would overwrite your changes.</p>
						</td>
					</tr>
					<tr>
						<th>Never auto-update</th>
						<td>
							<div style="max-height:220px;overflow:auto;border:1px solid #ddd;padding:8px;max-width:520px">
								<?php foreach ( get_plugins() as $file => $data ) : ?>
									<label style="display:block">
										<input type="checkbox" name="exclude[]" value="<?php echo esc_attr( $file ); ?>" <?php checked( in_array( $file, $exclude, true ) ); ?>>
										<?php echo esc_html( $data['Name'] ); ?>
									</label>
								<?php endforeach; ?>
							</div>
							<p class="description">For plugins that are customised, licence-locked, or that you update by hand.</p>
						</td>
					</tr>
				</table>

				<?php submit_button( 'Save settings' ); ?>
			</form>
		</div>
		<?php
	}
}
