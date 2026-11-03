<?php
/**
 * Removes everything this plugin stores when it is deleted from the Plugins
 * screen: the two custom tables, the settings and the prune event. Deactivating
 * the plugin keeps all of it.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- uninstall removes this plugin's own tables; there is no API for that.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}thessley_passkeys" );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- uninstall removes this plugin's own tables; there is no API for that.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}thessley_passkey_requests" );

delete_option( 'thessley_passkey_db_version' );
delete_option( 'thessley_passkey_mode' );
delete_option( 'thessley_passkey_identify' );

wp_clear_scheduled_hook( 'thessley_passkey_prune' );

// Transients: rate-limit windows, browser-binding tokens and TPM challenges.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- transients have no bulk-delete API; this is the documented pattern.
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '_transient_thessley_pk_%'
	    OR option_name LIKE '_transient_timeout_thessley_pk_%'"
);
