<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;
global $wpdb;
// Network activation is not supported; delete only this site's plugin-owned records.
$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'kodanote_mcp' ) . '`' );
$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'kodanote_mcp_audit' ) . '`' );
delete_option( 'kodanote_mcp_audit_schema' );
wp_clear_scheduled_hook( 'kodanote_mcp_cleanup' );
