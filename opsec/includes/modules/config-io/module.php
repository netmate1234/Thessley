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
 * Deliberately narrower than "every shieldcore_ option": runtime state (scan
 * results, snapshots, compiled country/CIDR caches, db-schema versions,
 * "last triggered" timestamps) is excluded everywhere it's identifiable,
 * since re-importing a stale scan result or overwriting a schema-version
 * marker on a different install is actively wrong, not just extra. Only
 * the values a module's own settings page actually lets an admin edit are
 * in scope.
 */
class ShieldCore_Module_Config_IO {

	const EXPORT_ACTION = 'shieldcore_cio_export';
	const IMPORT_ACTION  = 'shieldcore_cio_import';

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_post_shieldcore_cio_export', array( __CLASS__, 'handle_export' ) );
		add_action( 'admin_post_shieldcore_cio_import', array( __CLASS__, 'handle_import' ) );
		return __CLASS__;
	}

	/**
	 * module slug => option keys that module owns. geo-map and scan-all
	 * have no settings of their own (pure read-only view / aggregator) and
	 * aren't listed at all — nothing to export either way.
	 */
	private static function registry() {
		return array(
			'activity-log'    => array( 'shieldcore_activity_categories' ),
			'alerts'          => array( 'shieldcore_email_address', 'shieldcore_email_enabled', 'shieldcore_email_threshold', 'shieldcore_telegram_bot_token', 'shieldcore_telegram_chat_id', 'shieldcore_telegram_chat_name', 'shieldcore_telegram_enabled', 'shieldcore_telegram_threshold' ),
			'auto-update'     => array( 'shieldcore_auto_update_core', 'shieldcore_auto_update_exclude', 'shieldcore_auto_update_plugins', 'shieldcore_auto_update_themes' ),
			'bot-log'         => array( 'shieldcore_bot_log_retain_days' ),
			'event-log'       => array( 'shieldcore_event_log_retain_days' ),
			'file-integrity'  => array( 'shieldcore_integrity_check_baseline', 'shieldcore_integrity_check_core' ),
			'geo-blocker'     => array( 'shieldcore_geo_countries', 'shieldcore_geo_enforce_mode', 'shieldcore_geo_mode' ),
			'geo-login'       => array( 'shieldcore_geo_login_countries', 'shieldcore_geo_login_enforce_mode' ),
			'hardening'       => array( 'shieldcore_hardening_disable_file_edit', 'shieldcore_hardening_uploads_guard' ),
			'headers'         => array( 'shieldcore_headers_behind_proxy', 'shieldcore_headers_csp_policy', 'shieldcore_headers_csp_report_only', 'shieldcore_headers_enabled', 'shieldcore_headers_hsts_max_age', 'shieldcore_headers_hsts_preload', 'shieldcore_headers_hsts_subdomains' ),
			'ip-blocklist'    => array( 'shieldcore_ip_blocklist_mode', 'shieldcore_ip_blocklist_sources' ),
			'ip-sharing'      => array( 'shieldcore_unwantedip_api_key', 'shieldcore_unwantedip_enabled' ),
			'login-guard'     => array( 'shieldcore_login_guard_enabled', 'shieldcore_login_guard_escalate', 'shieldcore_login_guard_generic_errors', 'shieldcore_login_guard_lockout_min', 'shieldcore_login_guard_max_fails', 'shieldcore_login_guard_window_min' ),
			'malware-scanner' => array( 'shieldcore_malware_categories', 'shieldcore_malware_ignore_paths' ),
			'query-guard'     => array( 'shieldcore_qg_allow_jetpack', 'shieldcore_query_guard_block_xmlrpc', 'shieldcore_query_guard_categories', 'shieldcore_query_guard_mode', 'shieldcore_query_guard_post_scope', 'shieldcore_query_guard_scan_post' ),
			'rate-limiter'    => array( 'shieldcore_ratelimit_enabled', 'shieldcore_ratelimit_escalate', 'shieldcore_ratelimit_escalate_after', 'shieldcore_ratelimit_escalate_minutes', 'shieldcore_ratelimit_mode', 'shieldcore_ratelimit_per_minute' ),
			'user-enum'       => array( 'shieldcore_user_enum_block_author_scan', 'shieldcore_user_enum_block_rest_users', 'shieldcore_user_enum_disable_oembed_author', 'shieldcore_user_enum_hide_user_sitemap' ),
			'user-watchdog'   => array( 'shieldcore_user_watchdog_alerts', 'shieldcore_user_watchdog_email', 'shieldcore_user_watchdog_enabled' ),
			'vuln-scanner'    => array( 'shieldcore_vuln_check_directory', 'shieldcore_vuln_wpscan_token' ),
			'whitelist'       => array( 'shieldcore_ip_allowlist', 'shieldcore_trusted_networks_url' ),
		);
	}

	/** Real credentials — left out of an export unless explicitly opted in. */
	private static function secret_keys() {
		return array( 'shieldcore_telegram_bot_token', 'shieldcore_unwantedip_api_key', 'shieldcore_vuln_wpscan_token' );
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
			'plugin'      => 'shieldcore-security',
			'version'     => SHIELDCORE_VERSION,
			'site'        => home_url(),
			'exported_at' => gmdate( 'c' ),
			'modules'     => $data,
		);

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="shieldcore-security-config-' . gmdate( 'Y-m-d-His' ) . '.json"' );
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
					update_option( $key, self::sanitize_import_value( $values[ $key ] ) );
					$applied++;
				}
			}
		}

		self::redirect_back( array( 'cio_imported' => $applied ) );
	}

	/**
	 * A JSON import file is untrusted input, same as any other request body —
	 * the old code passed each value straight to update_option() with no
	 * validation, so a crafted file could store an arbitrary type against a
	 * boolean/int toggle, or unsafe markup into a string option (e.g. the
	 * CSP policy text, which headers/module.php later echoes into a real
	 * response header). This doesn't re-derive each module's own business
	 * rules (valid country codes, known category slugs, etc. — those still
	 * get re-validated the next time that module's own settings form is
	 * saved) — it only guarantees every value reaching update_option() here
	 * is one of the plain scalar/array shapes these options ever actually
	 * use, with string content run through the same tag-stripping every
	 * other text input in this plugin gets.
	 */
	private static function sanitize_import_value( $value, $depth = 0 ) {
		if ( $depth > 6 ) {
			return null;
		}
		if ( is_bool( $value ) ) {
			return $value;
		}
		if ( is_int( $value ) || is_float( $value ) ) {
			return $value;
		}
		if ( is_string( $value ) ) {
			return sanitize_text_field( $value );
		}
		if ( is_array( $value ) ) {
			$out = array();
			foreach ( $value as $k => $v ) {
				$out[ is_string( $k ) ? sanitize_text_field( $k ) : (int) $k ] = self::sanitize_import_value( $v, $depth + 1 );
			}
			return $out;
		}
		// null, or anything else JSON can't actually produce via json_decode()
		// with assoc=true (no objects survive that) — nothing left to keep.
		return null;
	}

	private static function redirect_back( array $args ) {
		wp_safe_redirect( add_query_arg( $args, wp_get_referer() ?: ShieldCore_Menu_Router::url( 'config-io' ) ) );
		exit;
	}

	public static function render_page() {
		ShieldCore_UI::open( 'config-io' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['cio_error'] ) ) {
			$messages = array(
				'no_file'      => 'Choose a file to import.',
				'too_large'    => 'File is too large (2MB max).',
				'invalid_file' => "That file doesn't look like an Opsec configuration export.",
			);
			$cio_error = sanitize_key( wp_unslash( $_GET['cio_error'] ) );
			ShieldCore_UI::notice( 'error', $messages[ $cio_error ] ?? 'Import failed.' );
		}
		if ( isset( $_GET['cio_imported'] ) ) {
			$n = (int) $_GET['cio_imported'];
			ShieldCore_UI::notice(
				$n ? 'success' : 'warning',
				$n ? sprintf( '%d setting(s) imported.', $n ) : 'Nothing was imported — no matching modules were selected.'
			);
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$registry = self::registry();
		?>

		<?php ShieldCore_UI::section( 'Export configuration', 'download' ); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( self::EXPORT_ACTION ); ?>
				<input type="hidden" name="action" value="shieldcore_cio_export">

				<?php
				ShieldCore_UI::row(
					'Modules to include',
					function () use ( $registry ) {
						self::module_checkboxes( $registry );
					},
					'Unchecked modules are left out of the file entirely.'
				);
				ShieldCore_UI::row(
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
		<?php ShieldCore_UI::section_end(); ?>

		<?php ShieldCore_UI::section( 'Import configuration', 'upload' ); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
				<?php wp_nonce_field( self::IMPORT_ACTION ); ?>
				<input type="hidden" name="action" value="shieldcore_cio_import">

				<?php
				ShieldCore_UI::row(
					'File',
					function () {
						?>
						<input type="file" name="config_file" accept="application/json,.json" required>
						<?php
					}
				);
				ShieldCore_UI::row(
					'Modules to apply',
					function () use ( $registry ) {
						self::module_checkboxes( $registry );
					},
					"Only these modules' settings are written, even if the file contains more — anything else in the file is ignored."
				);
				?>

				<?php submit_button( 'Upload and import', 'secondary' ); ?>
			</form>
		<?php ShieldCore_UI::section_end(); ?>

		<?php
		ShieldCore_UI::close();
	}

	private static function module_checkboxes( array $registry ) {
		echo '<div class="shieldcore-scroll">';
		foreach ( $registry as $slug => $keys ) {
			list( , $title ) = ShieldCore_UI::meta( $slug );
			printf(
				'<label><input type="checkbox" name="modules[]" value="%s" checked> %s</label>',
				esc_attr( $slug ),
				esc_html( $title )
			);
		}
		echo '</div>';
	}
}
