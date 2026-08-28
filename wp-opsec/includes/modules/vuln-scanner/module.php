<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Flags installed components that are plausible attack surface.
 *
 * Three signals, in decreasing order of certainty:
 *
 *  1. Outdated — an update is available. Taken from WordPress's own update
 *     data, so it's exact and needs no third-party service.
 *  2. Removed/abandoned — the plugin is gone from the .org directory (very
 *     often a pulled-for-security event) or hasn't been touched in years.
 *  3. Known CVEs — real vulnerability records, but this needs a WPScan API
 *     token. Optional: everything above still works without one.
 */
class WPOpsec_Module_Vuln_Scanner {

	const CRON_HOOK      = 'wpopsec_vuln_scan';
	const STALE_YEARS    = 2;
	const WPSCAN_API     = 'https://wpscan.com/api/v3/';

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 2 * HOUR_IN_SECONDS ), 'daily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'run_scan' ) );
		add_action( 'admin_post_wpopsec_vs_scan_now', array( __CLASS__, 'handle_scan_now' ) );
		add_action( 'admin_post_wpopsec_vs_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		return __CLASS__;
	}

	/** @return array<int,array> installed plugins + themes, normalised */
	private static function installed_components() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$out    = array();
		$active = (array) get_option( 'active_plugins', array() );

		foreach ( get_plugins() as $file => $data ) {
			$out[] = array(
				'type'    => 'plugin',
				'file'    => $file,
				'slug'    => dirname( $file ) !== '.' ? dirname( $file ) : basename( $file, '.php' ),
				'name'    => $data['Name'],
				'version' => $data['Version'],
				'active'  => in_array( $file, $active, true ),
			);
		}

		$current_theme = get_stylesheet();
		$parent_theme  = get_template();

		foreach ( wp_get_themes() as $slug => $theme ) {
			$out[] = array(
				'type'    => 'theme',
				'file'    => $slug,
				'slug'    => $slug,
				'name'    => $theme->get( 'Name' ),
				'version' => $theme->get( 'Version' ),
				'active'  => in_array( $slug, array( $current_theme, $parent_theme ), true ),
			);
		}

		return $out;
	}

	/** Pending updates, straight from WP's own update transients. */
	private static function pending_updates() {
		$out = array( 'plugins' => array(), 'themes' => array(), 'core' => null );

		if ( ! function_exists( 'get_plugin_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		wp_update_plugins();
		wp_update_themes();

		foreach ( (array) get_plugin_updates() as $file => $data ) {
			$out['plugins'][ $file ] = $data->update->new_version ?? '';
		}
		foreach ( (array) get_theme_updates() as $slug => $data ) {
			$out['themes'][ $slug ] = $data->update['new_version'] ?? '';
		}

		$core = get_site_transient( 'update_core' );
		if ( ! empty( $core->updates[0] ) && 'upgrade' === $core->updates[0]->response ) {
			$out['core'] = $core->updates[0]->current;
		}

		return $out;
	}

	/**
	 * @return array{closed:bool,last_updated:string,error:string}
	 */
	private static function directory_status( $slug ) {
		$cache_key = 'wpopsec_dirstat_' . md5( $slug );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			'https://api.wordpress.org/plugins/info/1.0/' . rawurlencode( $slug ) . '.json',
			array( 'timeout' => 15 )
		);

		$status = array( 'closed' => false, 'last_updated' => '', 'error' => '' );

		if ( is_wp_error( $response ) ) {
			$status['error'] = $response->get_error_message();
			// Don't cache transport failures for long — the plugin isn't
			// necessarily gone, we just couldn't reach the API.
			set_transient( $cache_key, $status, HOUR_IN_SECONDS );
			return $status;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! empty( $body['closed'] ) ) {
			$status['closed'] = true;
		}
		if ( ! empty( $body['last_updated'] ) ) {
			$status['last_updated'] = $body['last_updated'];
		}
		if ( isset( $body['error'] ) ) {
			// "Plugin not found" — either never on .org (custom/premium) or
			// removed. Reported as unknown rather than assumed malicious.
			$status['error'] = (string) $body['error'];
		}

		set_transient( $cache_key, $status, DAY_IN_SECONDS );
		return $status;
	}

	/** @return array{items:array,error:string} */
	private static function wpscan_lookup( $components ) {
		$token = trim( (string) get_option( 'wpopsec_vuln_wpscan_token', '' ) );
		if ( '' === $token ) {
			return array( 'items' => array(), 'error' => '' );
		}

		$found = array();
		$error = '';

		foreach ( $components as $c ) {
			if ( 'plugin' !== $c['type'] ) {
				continue; // themes use a different endpoint; plugins are the bulk of real risk
			}

			$cache_key = 'wpopsec_wpscan_' . md5( $c['slug'] . '|' . $c['version'] );
			$cached    = get_transient( $cache_key );
			if ( is_array( $cached ) ) {
				if ( $cached ) {
					$found[ $c['slug'] ] = $cached;
				}
				continue;
			}

			$response = wp_remote_get(
				self::WPSCAN_API . 'plugins/' . rawurlencode( $c['slug'] ),
				array(
					'timeout' => 20,
					'headers' => array( 'Authorization' => 'Token token=' . $token ),
				)
			);

			if ( is_wp_error( $response ) ) {
				$error = $response->get_error_message();
				break;
			}

			$code = wp_remote_retrieve_response_code( $response );
			if ( 429 === $code ) {
				$error = 'WPScan API rate limit reached — remaining components were skipped this run.';
				break;
			}
			if ( 401 === $code || 403 === $code ) {
				$error = 'WPScan API rejected the token.';
				break;
			}
			if ( 200 !== $code ) {
				set_transient( $cache_key, array(), HOUR_IN_SECONDS );
				continue;
			}

			$body  = json_decode( wp_remote_retrieve_body( $response ), true );
			$vulns = $body[ $c['slug'] ]['vulnerabilities'] ?? array();

			$relevant = array();
			foreach ( (array) $vulns as $v ) {
				$fixed = $v['fixed_in'] ?? null;
				// No fixed_in means unpatched — always relevant. Otherwise
				// only flag if the installed version predates the fix.
				if ( null === $fixed || version_compare( $c['version'], $fixed, '<' ) ) {
					$relevant[] = array(
						'title'    => $v['title'] ?? 'Unknown',
						'fixed_in' => $fixed,
					);
				}
			}

			set_transient( $cache_key, $relevant, DAY_IN_SECONDS );
			if ( $relevant ) {
				$found[ $c['slug'] ] = $relevant;
			}
		}

		return array( 'items' => $found, 'error' => $error );
	}

	public static function run_scan() {
		$components = self::installed_components();
		$updates    = self::pending_updates();

		$findings = array();

		foreach ( $components as $c ) {
			$issues = array();

			$new_version = 'plugin' === $c['type']
				? ( $updates['plugins'][ $c['file'] ] ?? null )
				: ( $updates['themes'][ $c['file'] ] ?? null );

			if ( $new_version ) {
				$issues[] = array(
					'kind'   => 'outdated',
					'detail' => sprintf( 'Update available: %s → %s', $c['version'], $new_version ),
				);
			}

			if ( 'plugin' === $c['type'] && get_option( 'wpopsec_vuln_check_directory', true ) ) {
				$status = self::directory_status( $c['slug'] );

				if ( $status['closed'] ) {
					$issues[] = array(
						'kind'   => 'closed',
						'detail' => 'Removed from the WordPress.org directory — often a pulled-for-security event.',
					);
				} elseif ( '' !== $status['last_updated'] ) {
					$ts = strtotime( $status['last_updated'] );
					if ( $ts && $ts < strtotime( '-' . self::STALE_YEARS . ' years' ) ) {
						$issues[] = array(
							'kind'   => 'stale',
							'detail' => sprintf( 'No release since %s — likely unmaintained.', date( 'Y-m-d', $ts ) ),
						);
					}
				}
			}

			if ( $issues ) {
				$findings[] = array_merge( $c, array( 'issues' => $issues ) );
			}
		}

		$wpscan = self::wpscan_lookup( $components );

		// Index by slug and assign through it: an earlier version walked
		// $findings by reference and left $f dangling when it took `continue 2`,
		// so a later by-value foreach over the same array overwrote the last
		// element on every iteration.
		$index_by_slug = array();
		foreach ( $findings as $i => $f ) {
			$index_by_slug[ $f['slug'] ] = $i;
		}

		foreach ( $wpscan['items'] as $slug => $vulns ) {
			$issues = array();
			foreach ( $vulns as $v ) {
				$issues[] = array(
					'kind'   => 'cve',
					'detail' => $v['title'] . ( $v['fixed_in'] ? sprintf( ' (fixed in %s)', $v['fixed_in'] ) : ' (no fix available)' ),
				);
			}

			if ( isset( $index_by_slug[ $slug ] ) ) {
				$findings[ $index_by_slug[ $slug ] ]['issues'] = array_merge(
					$findings[ $index_by_slug[ $slug ] ]['issues'],
					$issues
				);
				continue;
			}

			// Component had no other issue but does have a CVE.
			foreach ( $components as $c ) {
				if ( $c['slug'] === $slug ) {
					$findings[]                  = array_merge( $c, array( 'issues' => $issues ) );
					$index_by_slug[ $c['slug'] ] = count( $findings ) - 1;
					break;
				}
			}
		}

		$result = array(
			'at'            => time(),
			'core_update'   => $updates['core'],
			'findings'      => $findings,
			'scanned_count' => count( $components ),
			'wpscan_error'  => $wpscan['error'],
		);

		update_option( 'wpopsec_vuln_last_result', $result, false );

		$critical = 0;
		foreach ( $findings as $f ) {
			foreach ( $f['issues'] as $i ) {
				if ( in_array( $i['kind'], array( 'cve', 'closed' ), true ) ) {
					$critical++;
				}
			}
		}

		if ( $findings ) {
			wpopsec_log_event(
				'vuln-scanner',
				'scan_findings',
				'noted',
				sprintf( '%d component(s) flagged, %d high-severity, of %d scanned', count( $findings ), $critical, count( $components ) )
			);
		}

		return $result;
	}

	public static function handle_scan_now() {
		check_admin_referer( 'wpopsec_vs_scan_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::run_scan();
		wp_safe_redirect( add_query_arg( 'scanned', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_vs_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'wpopsec_vuln_check_directory', isset( $_POST['check_directory'] ) );
		update_option( 'wpopsec_vuln_wpscan_token', sanitize_text_field( wp_unslash( $_POST['wpscan_token'] ?? '' ) ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'Vulnerability Scan',
			'Vulnerability Scan',
			'manage_options',
			'wp-opsec-vuln-scanner',
			array( __CLASS__, 'render_page' )
		);
	}

	private static function kind_badge( $kind ) {
		$map = array(
			'cve'      => array( 'Known vulnerability', '#b32d2e' ),
			'closed'   => array( 'Removed from directory', '#b32d2e' ),
			'stale'    => array( 'Unmaintained', '#996800' ),
			'outdated' => array( 'Update available', '#996800' ),
		);
		list( $label, $color ) = $map[ $kind ] ?? array( $kind, '#666' );
		return '<span style="color:' . esc_attr( $color ) . ';font-weight:600">' . esc_html( $label ) . '</span>';
	}

	public static function render_page() {
		$last  = get_option( 'wpopsec_vuln_last_result', array() );
		$token = (string) get_option( 'wpopsec_vuln_wpscan_token', '' );
		?>
		<div class="wrap">
			<h1>WP Opsec — Vulnerability Scan</h1>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['scanned'] ) ) : ?>
				<div class="notice notice-success"><p>Scan complete.</p></div>
			<?php endif; ?>

			<?php if ( empty( $last ) ) : ?>
				<p>No scan has run yet.</p>
			<?php else : ?>
				<p>
					Last scan <?php echo esc_html( date( 'Y-m-d H:i', (int) $last['at'] ) ); ?> ·
					<?php echo esc_html( (int) $last['scanned_count'] ); ?> components checked ·
					<strong><?php echo esc_html( count( $last['findings'] ) ); ?></strong> flagged.
				</p>

				<?php if ( ! empty( $last['wpscan_error'] ) ) : ?>
					<div class="notice notice-warning inline"><p><?php echo esc_html( $last['wpscan_error'] ); ?></p></div>
				<?php endif; ?>

				<?php if ( ! empty( $last['core_update'] ) ) : ?>
					<div class="notice notice-warning inline">
						<p><strong>WordPress core update available:</strong> <?php echo esc_html( $last['core_update'] ); ?></p>
					</div>
				<?php endif; ?>

				<?php if ( empty( $last['findings'] ) ) : ?>
					<p style="color:#007017;font-weight:600">Nothing flagged.</p>
				<?php else : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th style="width:220px">Component</th>
								<th style="width:70px">Type</th>
								<th style="width:80px">Version</th>
								<th style="width:60px">Active</th>
								<th>Findings</th>
							</tr>
						</thead>
						<tbody>
						<?php foreach ( $last['findings'] as $f ) : ?>
							<tr>
								<td><strong><?php echo esc_html( $f['name'] ); ?></strong><br><code style="font-size:11px"><?php echo esc_html( $f['slug'] ); ?></code></td>
								<td><?php echo esc_html( $f['type'] ); ?></td>
								<td><?php echo esc_html( $f['version'] ); ?></td>
								<td><?php echo $f['active'] ? 'yes' : '<span style="color:#666">no</span>'; ?></td>
								<td>
									<?php foreach ( $f['issues'] as $issue ) : ?>
										<div style="margin-bottom:.3em">
											<?php echo self::kind_badge( $issue['kind'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
											— <?php echo esc_html( $issue['detail'] ); ?>
										</div>
									<?php endforeach; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
					<p class="description">An inactive plugin still has files on disk that can be reached directly — uninstall what you don't use rather than just deactivating it.</p>
				<?php endif; ?>
			<?php endif; ?>

			<p style="margin-top:1.5em">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_vs_scan_now' ); ?>
				<input type="hidden" name="action" value="wpopsec_vs_scan_now">
				<?php submit_button( 'Scan now', 'primary', 'submit', false ); ?>
			</form>
			</p>

			<h2>Settings</h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_vs_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_vs_save_settings">
				<table class="form-table">
					<tr>
						<th>Directory checks</th>
						<td>
							<label><input type="checkbox" name="check_directory" <?php checked( get_option( 'wpopsec_vuln_check_directory', true ) ); ?>> Check WordPress.org for removed / unmaintained plugins</label>
							<p class="description">Results are cached for a day. Plugins that were never on .org (premium, custom) are simply not reported on.</p>
						</td>
					</tr>
					<tr>
						<th><label for="wpopsec_wpscan">WPScan API token</label></th>
						<td>
							<input type="password" id="wpopsec_wpscan" name="wpscan_token" value="<?php echo esc_attr( $token ); ?>" style="width:26em" autocomplete="off">
							<p class="description">
								Optional. Adds real CVE data from <a href="https://wpscan.com/api" target="_blank" rel="noopener">wpscan.com/api</a> (free tier: 25 requests/day, which is why results are cached for 24h).
								Everything else on this page works without a token.
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
