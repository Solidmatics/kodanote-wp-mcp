<?php
/**
 * Plugin Name: Kodanote MCP
 * Description: Role-aware WordPress content, appearance and administration tools over MCP with OAuth and PKCE.
 * Version: 0.5.0
 * Requires at least: 6.5
 * Requires PHP: 8.1
 * Author: Kodanote
 * License: GPL-2.0-or-later
 * Text Domain: kodanote-mcp
 */

defined( 'ABSPATH' ) || exit;
define( 'KODANOTE_MCP_VERSION', '0.5.0' );
define( 'KODANOTE_MCP_FILE', __FILE__ );
foreach ( array( 'store', 'access', 'plugin', 'oauth', 'pattern-usage', 'pattern-tools', 'appearance-tools', 'navigation-tools', 'layout-tools', 'site-tools', 'audit', 'tools', 'server', 'admin' ) as $kodanote_mcp_class ) {
	require_once __DIR__ . '/includes/class-' . $kodanote_mcp_class . '.php';
}
unset( $kodanote_mcp_class );
register_activation_hook( __FILE__, array( 'Kodanote\\MCP\\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Kodanote\\MCP\\Plugin', 'deactivate' ) );
Kodanote\MCP\Plugin::boot();
