<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exports/imports every other module's settings as a single JSON file, with
 * each module optionally left out on either side — so a file can carry only
 * what's meant to move (e.g. IP Blocklist's mode without also overwriting
 * User Watchdog's alert list), and an import can apply only a subset of
 * what a file contains even if it carries more.
 *
 * Deliberately narrower than "every wpopsec_ option": runtime state (scan
 * results, snapshots, compiled country/CIDR caches, db-schema versions,
 * "last triggered" timestamps) is excluded everywhere it's identifiable,
 * since re-importing a stale scan result or overwriting a schema-version
 * marker on a different install is actively wrong, not just extra. Only
 * the values a module's own settings page actually lets an admin edit are
 * in scope.
 */
class WPOpsec_Module_Config_IO {

	const EXPORT_ACTION = 'wpopsec_cio_export';
	const IMPORT_ACTION  = 'wpopsec_cio_import';

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_post_wpopsec_cio_export', array( __CLASS__, 'handle_export' ) );
		add_action( 'admin_post_wpopsec_cio_import', array( __CLASS__, 'handle_import' ) );
		return __CLASS__;
	}

	/**
	 * module slug => option keys that module owns. geo-map and scan-all
	 * have no settings of their own (pure read-only view / aggregator) and
	 * aren't listed at all — nothing to export either way.
	 */
	private static function registry() {
		return array(
			'activity-log'    => array( 'wpopsec_activity_categories' ),
			'alerts'          => array( 'wpopsec_email_address', 'wpopsec_email_enabled', 'wpopsec_email_threshold', 'wpopsec_telegram_bot_token', 'wpopsec_telegram_chat_id', 'wpopsec_telegram_chat_name', 'wpopsec_telegram_enabled', 'wpopsec_telegram_threshold' ),
			'auto-update'     => array( 'wpopsec_auto_update_core', 'wpopsec_auto_update_exclude', 'wpopsec_auto_update_plugins', 'wpopsec_auto_update_themes' ),
			'bot-log'         => array( 'wpopsec_bot_log_retain_days' ),
			'event-log'       => array( 'wpopsec_event_log_retain_days' ),
			'file-integrity'  => array( 'wpopsec_integrity_check_baseline', 'wpopsec_integrity_check_core' ),
			'geo-blocker'     => array( 'wpopsec_geo_countries', 'wpopsec_geo_enforce_mode', 'wpopsec_geo_mode' ),
			'geo-login'       => array( 'wpopsec_geo_login_countries', 'wpopsec_geo_login_enforce_mode' ),
			'hardening'       => array( 'wpopsec_hardening_disable_file_edit', 'wpopsec_hardening_uploads_guard' ),
			'headers'         => array( 'wpopsec_headers_behind_proxy', 'wpopsec_headers_csp_policy', 'wpopsec_headers_csp_report_only', 'wpopsec_headers_enabled', 'wpopsec_headers_hsts_max_age', 'wpopsec_headers_hsts_preload', 'wpopsec_headers_hsts_subdomains' ),
			'ip-blocklist'    => array( 'wpopsec_ip_blocklist_mode', 'wpopsec_ip_blocklist_sources' ),
			'ip-sharing'      => array( 'wpopsec_unwantedip_api_key', 'wpopsec_unwantedip_enabled' ),
			'login-guard'     => array( 'wpopsec_login_guard_enabled', 'wpopsec_login_guard_escalate', 'wpopsec_login_guard_generic_errors', 'wpopsec_login_guard_lockout_min', 'wpopsec_login_guard_max_fails', 'wpopsec_login_guard_window_min' ),
			'malware-scanner' => array( 'wpopsec_malware_categories', 'wpopsec_malware_ignore_paths' ),
			'query-guard'     => array( 'wpopsec_qg_allow_jetpack', 'wpopsec_query_guard_block_xmlrpc', 'wpopsec_query_guard_categories', 'wpopsec_query_guard_mode', 'wpopsec_query_guard_post_scope', 'wpopsec_query_guard_scan_post' ),
			'rate-limiter'    => array( 'wpopsec_ratelimit_enabled', 'wpopsec_ratelimit_escalate', 'wpopsec_ratelimit_escalate_after', 'wpopsec_ratelimit_escalate_minutes', 'wpopsec_ratelimit_mode', 'wpopsec_ratelimit_per_minute' ),
			'user-enum'       => array( 'wpopsec_user_enum_block_author_scan', 'wpopsec_user_enum_block_rest_users', 'wpopsec_user_enum_disable_oembed_author', 'wpopsec_user_enum_hide_user_sitemap' ),
			'user-watchdog'   => array( 'wpopsec_user_watchdog_alerts', 'wpopsec_user_watchdog_email', 'wpopsec_user_watchdog_enabled' ),
			'vuln-scanner'    => array( 'wpopsec_vuln_check_directory', 'wpopsec_vuln_wpscan_token' ),
			'whitelist'       => array( 'wpopsec_ip_allowlist', 'wpopsec_trusted_networks_url' ),
		);
	}

	/** Real credentials — left out of an export unless explicitly opted in. */
	private static function secret_keys() {
		return array( 'wpopsec_telegram_bot_token', 'wpopsec_unwantedip_api_key', 'wpopsec_vuln_wpscan_token' );
	}

	public static function handle_export() {
		check_admin_referer( self::EXPORT_ACTION );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$selected       = isset( $_POST['modules'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['modules'] ) ) : array();
		$include_secret = ! empty( $_POST['include_secrets'] );
		$secret_keys    = self::secret_keys();

		$data = array();
		foreach ( self::registry() as $slug => $keys ) {
			if ( ! in_array( $slug, $selected, true ) ) {
				continue;
			}
			$values = array();
			foreach ( $keys as $key ) {
				if ( in_array( $key, $secret_keys, true ) && ! $include_secret ) {
					continue;
				}
				$values[ $key ] = get_option( $key );
			}
			if ( $values ) {
				$data[ $slug ] = $values;
			}
		}

		$payload = array(
			'plugin'      => 'opsec',
			'version'     => WPOPSEC_VERSION,
			'site'        => home_url(),
			'exported_at' => gmdate( 'c' ),
			'modules'     => $data,
		);

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="opsec-config-' . gmdate( 'Y-m-d-His' ) . '.json"' );
		echo wp_json_encode( $payload, JSON_PRETTY_PRINT );
		exit;
	}

	public static function handle_import() {
		check_admin_referer( self::IMPORT_ACTION );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- the leading isset( $_FILES['config_file'] ) short-circuits (via ||) before ['error'] is ever read, so it can't be undefined here.
		if ( ! isset( $_FILES['config_file'] ) || empty( $_FILES['config_file']['tmp_name'] ) || UPLOAD_ERR_OK !== $_FILES['config_file']['error'] ) {
			self::redirect_back( array( 'cio_error' => 'no_file' ) );
		}

		// 2MB is generous for a JSON options dump — guards against something
		// large being uploaded through a field with no other size check.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- $_FILES['config_file'] is already confirmed to exist by the isset() check above (this function would have exited via redirect_back() otherwise).
		if ( $_FILES['config_file']['size'] > 2 * MB_IN_BYTES ) {
			self::redirect_back( array( 'cio_error' => 'too_large' ) );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a server-generated temp file path from PHP's own upload handling, not user-controlled string content.
		$json = json_decode( (string) file_get_contents( $_FILES['config_file']['tmp_name'] ), true );

		if ( ! is_array( $json ) || 'opsec' !== ( $json['plugin'] ?? '' ) || ! is_array( $json['modules'] ?? null ) ) {
			self::redirect_back( array( 'cio_error' => 'invalid_file' ) );
		}

		$selected = isset( $_POST['modules'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['modules'] ) ) : array();
		$registry = self::registry();

		$applied = 0;
		foreach ( $json['modules'] as $slug => $values ) {
			if ( ! in_array( $slug, $selected, true ) || ! isset( $registry[ $slug ] ) || ! is_array( $values ) ) {
				continue;
			}
			// Only ever write keys this module actually owns, per our own
			// registry — a hand-edited or tampered file can't use a fake
			// or mismatched module name to reach an option outside it.
			foreach ( $registry[ $slug ] as $key ) {
				if ( array_key_exists( $key, $values ) ) {
					update_option( $key, $values[ $key ] );
					$applied++;
				}
			}
		}

		self::redirect_back( array( 'cio_imported' => $applied ) );
	}

	private static function redirect_back( array $args ) {
		wp_safe_redirect( add_query_arg( $args, wp_get_referer() ?: WPOpsec_Menu_Router::url( 'config-io' ) ) );
		exit;
	}

	public static function render_page() {
		WPOpsec_UI::open( 'config-io' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['cio_error'] ) ) {
			$messages = array(
				'no_file'      => 'Choose a file to import.',
				'too_large'    => 'File is too large (2MB max).',
				'invalid_file' => "That file doesn't look like an Opsec configuration export.",
			);
			$cio_error = sanitize_key( wp_unslash( $_GET['cio_error'] ) );
			WPOpsec_UI::notice( 'error', $messages[ $cio_error ] ?? 'Import failed.' );
		}
		if ( isset( $_GET['cio_imported'] ) ) {
			$n = (int) $_GET['cio_imported'];
			WPOpsec_UI::notice(
				$n ? 'success' : 'warning',
				$n ? sprintf( '%d setting(s) imported.', $n ) : 'Nothing was imported — no matching modules were selected.'
			);
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$registry = self::registry();
		?>

		<?php WPOpsec_UI::section( 'Export configuration', 'download' ); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( self::EXPORT_ACTION ); ?>
				<input type="hidden" name="action" value="wpopsec_cio_export">

				<?php
				WPOpsec_UI::row(
					'Modules to include',
					function () use ( $registry ) {
						self::module_checkboxes( $registry );
					},
					'Unchecked modules are left out of the file entirely.'
				);
				WPOpsec_UI::row(
					'API keys / tokens',
					function () {
						?>
						<label><input type="checkbox" name="include_secrets" checked> Include Telegram bot token, unwantedip API key, and WPScan token</label>
						<?php
					},
					"These are real credentials for this site — uncheck if this file is going somewhere you don't fully trust."
				);
				?>

				<?php submit_button( 'Download export' ); ?>
			</form>
		<?php WPOpsec_UI::section_end(); ?>

		<?php WPOpsec_UI::section( 'Import configuration', 'upload' ); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
				<?php wp_nonce_field( self::IMPORT_ACTION ); ?>
				<input type="hidden" name="action" value="wpopsec_cio_import">

				<?php
				WPOpsec_UI::row(
					'File',
					function () {
						?>
						<input type="file" name="config_file" accept="application/json,.json" required>
						<?php
					}
				);
				WPOpsec_UI::row(
					'Modules to apply',
					function () use ( $registry ) {
						self::module_checkboxes( $registry );
					},
					"Only these modules' settings are written, even if the file contains more — anything else in the file is ignored."
				);
				?>

				<?php submit_button( 'Upload and import', 'secondary' ); ?>
			</form>
		<?php WPOpsec_UI::section_end(); ?>

		<?php
		WPOpsec_UI::close();
	}

	private static function module_checkboxes( array $registry ) {
		echo '<div class="wpopsec-scroll">';
		foreach ( $registry as $slug => $keys ) {
			list( , $title ) = WPOpsec_UI::meta( $slug );
			printf(
				'<label><input type="checkbox" name="modules[]" value="%s" checked> %s</label>',
				esc_attr( $slug ),
				esc_html( $title )
			);
		}
		echo '</div>';
	}
}
