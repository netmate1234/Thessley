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

$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}thessley_passkeys" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}thessley_passkey_requests" );

delete_option( 'thessley_passkey_db_version' );
delete_option( 'thessley_passkey_mode' );
delete_option( 'thessley_passkey_identify' );

wp_clear_scheduled_hook( 'thessley_passkey_prune' );

// Transients: rate-limit windows, browser-binding tokens and TPM challenges.
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '_transient_thessley_pk_%'
	    OR option_name LIKE '_transient_timeout_thessley_pk_%'"
);
