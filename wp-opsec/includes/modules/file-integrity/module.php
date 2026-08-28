<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * File integrity monitoring.
 *
 * Two independent checks, because they answer different questions:
 *
 *  - Core files are verified against WordPress.org's published checksums.
 *    That's authoritative: it detects tampering even if the attacker got
 *    in before this plugin was ever installed.
 *  - Plugins/themes/uploads have no published checksums, so those are
 *    compared against a baseline snapshot taken on this site. That only
 *    detects change *since the baseline*, which is why the baseline is
 *    re-taken explicitly (after an update) rather than silently.
 */
class WPOpsec_Module_File_Integrity {

	const CRON_HOOK  = 'wpopsec_file_integrity_scan';
	const DB_VERSION = 1;
	const TIME_LIMIT = 25; // seconds per scan pass, to stay well inside PHP limits

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'wpopsec_baseline';
	}

	public static function activate() {
		self::install_table();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		if ( (int) get_option( 'wpopsec_integrity_db_version', 0 ) !== self::DB_VERSION ) {
			self::install_table();
		}

		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'run_scan' ) );
		add_action( 'admin_post_wpopsec_fi_scan_now', array( __CLASS__, 'handle_scan_now' ) );
		add_action( 'admin_post_wpopsec_fi_rebaseline', array( __CLASS__, 'handle_rebaseline' ) );
		add_action( 'admin_post_wpopsec_fi_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		return __CLASS__;
	}

	public static function install_table() {
		global $wpdb;

		$collate = $wpdb->get_charset_collate();
		$table   = self::table();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		// path_hash is an indexed md5 of the path: real paths can exceed
		// MySQL's index key length, so index the digest instead.
		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				path_hash char(32) NOT NULL,
				path varchar(500) NOT NULL,
				file_hash char(32) NOT NULL,
				size bigint(20) unsigned NOT NULL DEFAULT 0,
				recorded_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY path_hash (path_hash)
			) {$collate};"
		);

		update_option( 'wpopsec_integrity_db_version', self::DB_VERSION, false );
	}

	/**
	 * Directories to baseline. Entries are relative to ABSPATH when the
	 * content directory lives inside it, and absolute otherwise —
	 * WP_CONTENT_DIR is allowed to sit outside ABSPATH, and a naive
	 * str_replace there produced a path that never resolved, so plugins and
	 * themes were skipped while the UI still reported "no changes".
	 */
	private static function scan_roots() {
		$roots = array( 'wp-admin', 'wp-includes' );

		$abs     = trailingslashit( ABSPATH );
		$content = trailingslashit( WP_CONTENT_DIR );
		$inside  = ( 0 === strpos( $content, $abs ) );
		$base    = $inside ? substr( $content, strlen( $abs ) ) : $content;
		$base    = rtrim( $base, '/' );

		foreach ( array( 'plugins', 'themes', 'mu-plugins' ) as $sub ) {
			$roots[] = $base . '/' . $sub;
		}

		return $roots;
	}

	private static function watched_extensions() {
		return array( 'php', 'phtml', 'phar', 'js', 'htaccess' );
	}

	/**
	 * @return array{files:array<string,array{hash:string,size:int}>, partial:bool, errors:string[]}
	 *
	 * `partial` is the important part of the contract: a crawl cut short by
	 * the time budget must never be compared against a complete baseline, or
	 * every file it didn't reach looks deleted. Callers have to check it.
	 */
	public static function collect_files() {
		$files    = array();
		$errors   = array();
		$partial  = false;
		$abs  = trailingslashit( ABSPATH );
		$exts = self::watched_extensions();

		// Filterable so a large site that legitimately can't finish in the
		// default budget can raise it rather than living with permanently
		// partial scans (which suppress deleted-file detection).
		$budget   = max( 1, (int) apply_filters( 'wpopsec_integrity_time_limit', self::TIME_LIMIT ) );
		$deadline = time() + $budget;

		// Root-level PHP (wp-config.php, index.php, xmlrpc.php, ...)
		foreach ( (array) glob( $abs . '*.php' ) as $file ) {
			$files[ self::relative_path( $file ) ] = self::file_info( $file );
		}

		foreach ( self::scan_roots() as $root ) {
			$dir = self::root_to_dir( $root );
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
					// SELF_FIRST so directories are visited too: CATCH_GET_CHILD
					// stops an unreadable one from throwing, but it also
					// swallows it silently, and a directory we couldn't read is
					// exactly the case that must not be mistaken for "no files
					// here". Seeing the directory lets us flag it.
					RecursiveIteratorIterator::SELF_FIRST,
					RecursiveIteratorIterator::CATCH_GET_CHILD
				);

				foreach ( $iter as $file ) {
					if ( time() > $deadline ) {
						$partial  = true;
						$errors[] = sprintf( 'time limit (%ds) reached while scanning %s — raise it with the wpopsec_integrity_time_limit filter', $budget, $root );
						break 2;
					}

					if ( $file->isDir() ) {
						if ( ! $file->isReadable() ) {
							$partial  = true;
							$errors[] = sprintf( 'directory not readable, contents unchecked: %s', self::relative_path( $file->getPathname() ) );
						}
						continue;
					}

					if ( ! $file->isFile() ) {
						continue;
					}
					$ext = strtolower( $file->getExtension() );
					if ( ! in_array( $ext, $exts, true ) && '.htaccess' !== $file->getFilename() ) {
						continue;
					}
					$path           = self::relative_path( $file->getPathname() );
					$files[ $path ] = self::file_info( $file->getPathname() );
				}
			} catch ( Exception $e ) {
				// Unreadable root, or anything else the iterator couldn't
				// recover from: report it rather than returning a short list
				// that would read as "files were deleted".
				$partial  = true;
				$errors[] = sprintf( 'could not fully read %s: %s', $root, $e->getMessage() );
			}
		}

		return array( 'files' => $files, 'partial' => $partial, 'errors' => $errors );
	}

	/** Path as stored in the baseline: relative to ABSPATH when inside it. */
	private static function relative_path( $absolute ) {
		$abs = trailingslashit( ABSPATH );
		return 0 === strpos( $absolute, $abs ) ? substr( $absolute, strlen( $abs ) ) : $absolute;
	}

	/** Roots may be relative to ABSPATH or absolute (wp-content moved out). */
	private static function root_to_dir( $root ) {
		return ( '/' === substr( $root, 0, 1 ) ) ? $root : trailingslashit( ABSPATH ) . $root;
	}

	private static function file_info( $path ) {
		return array(
			'hash' => (string) @md5_file( $path ),
			'size' => (int) @filesize( $path ),
		);
	}

	public static function rebaseline() {
		global $wpdb;

		$scan  = self::collect_files();
		$files = $scan['files'];
		$table = self::table();
		$now   = current_time( 'mysql' );

		// Refuse to overwrite a good baseline with a truncated crawl: the
		// missing files would show up as "added" on the next scan, which is
		// indistinguishable from an attacker dropping files.
		if ( $scan['partial'] ) {
			wpopsec_log_event(
				'file-integrity',
				'baseline_aborted',
				'noted',
				'incomplete crawl, baseline left unchanged: ' . implode( '; ', $scan['errors'] )
			);
			return new WP_Error( 'wpopsec_partial_scan', implode( '; ', $scan['errors'] ) );
		}

		$wpdb->query( "TRUNCATE TABLE {$table}" );

		foreach ( array_chunk( array_keys( $files ), 200 ) as $chunk ) {
			$values = array();
			foreach ( $chunk as $path ) {
				$values[] = $wpdb->prepare(
					'(%s,%s,%s,%d,%s)',
					md5( $path ),
					substr( $path, 0, 500 ),
					$files[ $path ]['hash'],
					$files[ $path ]['size'],
					$now
				);
			}
			$wpdb->query( "INSERT INTO {$table} (path_hash,path,file_hash,size,recorded_at) VALUES " . implode( ',', $values ) );
		}

		update_option( 'wpopsec_integrity_baseline_at', time(), false );
		update_option( 'wpopsec_integrity_baseline_count', count( $files ), false );

		wpopsec_log_event( 'file-integrity', 'baseline_taken', 'noted', sprintf( '%d files hashed', count( $files ) ) );

		return count( $files );
	}

	/**
	 * Verify core files against WordPress.org's published checksums.
	 * @return array{checked:int,modified:array,missing:array,error:string}
	 */
	public static function verify_core() {
		global $wp_version;

		$locale = get_locale();
		$url    = add_query_arg(
			array( 'version' => $wp_version, 'locale' => $locale ),
			'https://api.wordpress.org/core/checksums/1.0/'
		);

		$response = wp_remote_get( $url, array( 'timeout' => 20 ) );
		if ( is_wp_error( $response ) ) {
			return array( 'checked' => 0, 'modified' => array(), 'missing' => array(), 'error' => $response->get_error_message() );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
			return array( 'checked' => 0, 'modified' => array(), 'missing' => array(), 'error' => 'No checksums returned for this version/locale.' );
		}

		$modified = array();
		$missing  = array();
		$abs      = trailingslashit( ABSPATH );

		foreach ( $body['checksums'] as $file => $expected ) {
			// wp-content is deliberately excluded: it's the user's own files,
			// and the checksum list covers only shipped defaults there.
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$path = $abs . $file;
			if ( ! file_exists( $path ) ) {
				$missing[] = $file;
				continue;
			}
			if ( @md5_file( $path ) !== $expected ) {
				$modified[] = $file;
			}
		}

		return array(
			'checked'  => count( $body['checksums'] ),
			'modified' => $modified,
			'missing'  => $missing,
			'error'    => '',
		);
	}

	/** Compare current files against the stored baseline. */
	public static function diff_baseline() {
		global $wpdb;

		$table = self::table();
		$rows  = $wpdb->get_results( "SELECT path, file_hash, size FROM {$table}", ARRAY_A );
		if ( empty( $rows ) ) {
			return array( 'added' => array(), 'modified' => array(), 'deleted' => array(), 'no_baseline' => true );
		}

		$baseline = array();
		foreach ( $rows as $row ) {
			$baseline[ $row['path'] ] = $row['file_hash'];
		}

		$scan     = self::collect_files();
		$current  = $scan['files'];
		$added    = array();
		$modified = array();

		foreach ( $current as $path => $info ) {
			if ( ! isset( $baseline[ $path ] ) ) {
				$added[] = $path;
			} elseif ( $baseline[ $path ] !== $info['hash'] ) {
				$modified[] = $path;
			}
		}

		// Only meaningful if the crawl actually finished. On a partial pass
		// everything not reached would otherwise be reported as deleted.
		$deleted = $scan['partial']
			? array()
			: array_values( array_diff( array_keys( $baseline ), array_keys( $current ) ) );

		return array(
			'added'       => $added,
			'modified'    => $modified,
			'deleted'     => $deleted,
			'no_baseline' => false,
			'partial'     => $scan['partial'],
			'errors'      => $scan['errors'],
		);
	}

	public static function run_scan() {
		$result = array( 'at' => time() );

		if ( get_option( 'wpopsec_integrity_check_core', true ) ) {
			$core             = self::verify_core();
			$result['core']   = $core;
			$core_problems    = count( $core['modified'] ) + count( $core['missing'] );

			if ( $core_problems > 0 ) {
				wpopsec_log_event(
					'file-integrity',
					'core_mismatch',
					'noted',
					sprintf( '%d modified, %d missing vs WordPress.org checksums: %s', count( $core['modified'] ), count( $core['missing'] ), implode( ', ', array_slice( array_merge( $core['modified'], $core['missing'] ), 0, 5 ) ) )
				);
			}
		}

		if ( get_option( 'wpopsec_integrity_check_baseline', true ) ) {
			$diff             = self::diff_baseline();
			$result['diff']   = $diff;

			if ( ! empty( $diff['partial'] ) ) {
				wpopsec_log_event(
					'file-integrity',
					'scan_incomplete',
					'noted',
					'results are partial and may under-report: ' . implode( '; ', (array) $diff['errors'] )
				);
			}

			if ( empty( $diff['no_baseline'] ) ) {
				$changes = count( $diff['added'] ) + count( $diff['modified'] ) + count( $diff['deleted'] );
				if ( $changes > 0 ) {
					wpopsec_log_event(
						'file-integrity',
						'baseline_drift',
						'noted',
						sprintf(
							'%d added, %d modified, %d deleted since baseline: %s',
							count( $diff['added'] ),
							count( $diff['modified'] ),
							count( $diff['deleted'] ),
							implode( ', ', array_slice( array_merge( $diff['added'], $diff['modified'] ), 0, 5 ) )
						)
					);
				}
			}
		}

		update_option( 'wpopsec_integrity_last_result', $result, false );

		return $result;
	}

	public static function handle_scan_now() {
		check_admin_referer( 'wpopsec_fi_scan_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::run_scan();
		wp_safe_redirect( add_query_arg( 'scanned', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_rebaseline() {
		check_admin_referer( 'wpopsec_fi_rebaseline' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$result = self::rebaseline();
		if ( is_wp_error( $result ) ) {
			wp_safe_redirect( add_query_arg( 'rebaselined', 'partial', wp_get_referer() ) );
			exit;
		}

		self::run_scan();
		wp_safe_redirect( add_query_arg( 'rebaselined', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_fi_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		update_option( 'wpopsec_integrity_check_core', isset( $_POST['check_core'] ) );
		update_option( 'wpopsec_integrity_check_baseline', isset( $_POST['check_baseline'] ) );
		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function admin_menu() {
		add_submenu_page(
			'wp-opsec',
			'File Integrity',
			'File Integrity',
			'manage_options',
			'wp-opsec-file-integrity',
			array( __CLASS__, 'render_page' )
		);
	}

	private static function render_file_list( $label, $files, $tone = 'normal' ) {
		if ( empty( $files ) ) {
			return;
		}
		$color = 'critical' === $tone ? '#b32d2e' : '#996800';
		echo '<p style="color:' . esc_attr( $color ) . ';font-weight:600;margin-bottom:.3em">' . esc_html( $label ) . ' (' . count( $files ) . ')</p>';
		echo '<ul style="margin:0 0 1em 1.5em;list-style:disc">';
		foreach ( array_slice( $files, 0, 50 ) as $f ) {
			echo '<li><code>' . esc_html( $f ) . '</code></li>';
		}
		if ( count( $files ) > 50 ) {
			echo '<li>… and ' . esc_html( count( $files ) - 50 ) . ' more</li>';
		}
		echo '</ul>';
	}

	public static function render_page() {
		$last          = get_option( 'wpopsec_integrity_last_result', array() );
		$baseline_at   = (int) get_option( 'wpopsec_integrity_baseline_at', 0 );
		$baseline_ct   = (int) get_option( 'wpopsec_integrity_baseline_count', 0 );
		?>
		<div class="wrap">
			<h1>WP Opsec — File Integrity</h1>

			<?php if ( isset( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success"><p>Settings saved.</p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['scanned'] ) ) : ?>
				<div class="notice notice-success"><p>Scan complete.</p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['rebaselined'] ) && 'partial' === $_GET['rebaselined'] ) : ?>
				<div class="notice notice-error"><p>The scan couldn't read every file, so the baseline was left unchanged — replacing it with a partial crawl would make the unread files look like new files on the next scan. See the incomplete-scan note below.</p></div>
			<?php elseif ( isset( $_GET['rebaselined'] ) ) : ?>
				<div class="notice notice-success"><p>Baseline re-taken.</p></div>
			<?php endif; ?>

			<?php if ( ! empty( $last['diff']['partial'] ) ) : ?>
				<div class="notice notice-warning">
					<p><strong>Last scan was incomplete</strong> — results below may under-report:</p>
					<ul style="margin-left:1.5em;list-style:disc">
						<?php foreach ( (array) $last['diff']['errors'] as $err ) : ?>
							<li><?php echo esc_html( $err ); ?></li>
						<?php endforeach; ?>
					</ul>
					<p>Deleted-file detection is skipped while a scan is partial. If this is the time limit, the site has more files than one pass can hash.</p>
				</div>
			<?php endif; ?>

			<h2>Core files</h2>
			<p class="description">Verified against WordPress.org's published checksums for your exact version and locale — authoritative, and valid even if this plugin was installed after a compromise.</p>
			<?php if ( empty( $last['core'] ) ) : ?>
				<p>Not checked yet.</p>
			<?php elseif ( ! empty( $last['core']['error'] ) ) : ?>
				<div class="notice notice-warning inline"><p><?php echo esc_html( $last['core']['error'] ); ?></p></div>
			<?php elseif ( empty( $last['core']['modified'] ) && empty( $last['core']['missing'] ) ) : ?>
				<p style="color:#007017;font-weight:600">All <?php echo esc_html( number_format_i18n( $last['core']['checked'] ) ); ?> core files match.</p>
			<?php else : ?>
				<?php self::render_file_list( 'Modified core files', $last['core']['modified'], 'critical' ); ?>
				<?php self::render_file_list( 'Missing core files', $last['core']['missing'], 'critical' ); ?>
				<p class="description">Reinstalling WordPress from Dashboard → Updates → "Re-install now" restores core files without touching your content.</p>
			<?php endif; ?>

			<h2>Plugins, themes &amp; mu-plugins</h2>
			<p class="description">
				No published checksums exist for these, so they're compared against a snapshot taken on this site.
				<?php if ( $baseline_at ) : ?>
					Baseline: <?php echo esc_html( number_format_i18n( $baseline_ct ) ); ?> files, taken <?php echo esc_html( date( 'Y-m-d H:i', $baseline_at ) ); ?>.
				<?php else : ?>
					<strong>No baseline taken yet.</strong>
				<?php endif; ?>
			</p>
			<?php if ( empty( $last['diff'] ) ) : ?>
				<p>Not checked yet.</p>
			<?php elseif ( ! empty( $last['diff']['no_baseline'] ) ) : ?>
				<p>Take a baseline to start detecting changes.</p>
			<?php else : ?>
				<?php $d = $last['diff']; ?>
				<?php if ( empty( $d['added'] ) && empty( $d['modified'] ) && empty( $d['deleted'] ) ) : ?>
					<p style="color:#007017;font-weight:600">No changes since the baseline.</p>
				<?php else : ?>
					<?php self::render_file_list( 'Added', $d['added'], 'critical' ); ?>
					<?php self::render_file_list( 'Modified', $d['modified'], 'critical' ); ?>
					<?php self::render_file_list( 'Deleted', $d['deleted'] ); ?>
					<p class="description">Updating or installing a plugin/theme legitimately changes these files. Re-take the baseline after you've done so, once you've confirmed the changes are yours.</p>
				<?php endif; ?>
			<?php endif; ?>

			<p style="margin-top:1.5em">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
				<?php wp_nonce_field( 'wpopsec_fi_scan_now' ); ?>
				<input type="hidden" name="action" value="wpopsec_fi_scan_now">
				<?php submit_button( 'Scan now', 'primary', 'submit', false ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;margin-left:.5em"
				onsubmit="return confirm('Re-take the baseline? Current files become the new known-good reference — only do this if you trust the current state.');">
				<?php wp_nonce_field( 'wpopsec_fi_rebaseline' ); ?>
				<input type="hidden" name="action" value="wpopsec_fi_rebaseline">
				<?php submit_button( 'Take / re-take baseline', 'secondary', 'submit', false ); ?>
			</form>
			</p>

			<h2>Settings</h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_fi_save_settings' ); ?>
				<input type="hidden" name="action" value="wpopsec_fi_save_settings">
				<table class="form-table">
					<tr>
						<th>Daily scan checks</th>
						<td>
							<label><input type="checkbox" name="check_core" <?php checked( get_option( 'wpopsec_integrity_check_core', true ) ); ?>> Core files vs WordPress.org checksums</label><br>
							<label><input type="checkbox" name="check_baseline" <?php checked( get_option( 'wpopsec_integrity_check_baseline', true ) ); ?>> Plugins/themes vs local baseline</label>
							<p class="description">Findings are written to the Event Log.</p>
						</td>
					</tr>
				</table>
				<?php submit_button( 'Save settings' ); ?>
			</form>
		</div>
		<?php
	}
}
