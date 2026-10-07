<?php
namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Plugin {
	public static function boot(): void {
		add_action( 'init', array( Audit::class, 'maybe_install' ), 1 );
		// OAuth HTTP Basic identifies an OAuth client, not a WordPress Application Password user.
		add_filter( 'application_password_is_api_request', static function ( $is_api ) {
			$route = $GLOBALS['wp']->query_vars['rest_route'] ?? ( $_GET['rest_route'] ?? '' );
			$path = wp_parse_url( $_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH );
			foreach ( array( 'token', 'revoke' ) as $endpoint ) {
				if ( is_string( $route ) && '' !== $route ) {
					if ( '/kodanote-mcp/v1/oauth/' . $endpoint === rtrim( $route, '/' ) ) { return false; }
					continue;
				}
				$url = self::oauth_url( $endpoint );
				if ( ! wp_parse_url( $url, PHP_URL_QUERY ) && rtrim( (string) wp_parse_url( $url, PHP_URL_PATH ), '/' ) === rtrim( (string) $path, '/' ) ) { return false; }
			}
			return $is_api;
		} );
		add_action( 'rest_api_init', array( OAuth::class, 'register_routes' ) );
		add_action( 'rest_api_init', array( Server::class, 'register_routes' ) );
		add_action( 'admin_post_kodanote_mcp_authorize', array( OAuth::class, 'authorize' ) );
		add_action( 'admin_post_nopriv_kodanote_mcp_authorize', array( OAuth::class, 'authorize' ) );
		add_action( 'parse_request', array( self::class, 'discovery' ), 0 );
		add_action( 'kodanote_mcp_cleanup', array( Store::class, 'cleanup' ) );
		add_action( 'kodanote_mcp_cleanup', array( Audit::class, 'cleanup' ) );
		Admin::boot();
		Pattern_Usage::boot();
	}

	public static function activate( bool $network_wide = false ): void {
		if ( $network_wide ) { wp_die( 'Activate Kodanote MCP individually on each site; network activation is not supported.' ); }
		Store::install();
		Audit::install();
		if ( ! wp_next_scheduled( 'kodanote_mcp_cleanup' ) ) { wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'kodanote_mcp_cleanup' ); }
	}

	public static function deactivate(): void {
		wp_clear_scheduled_hook( 'kodanote_mcp_cleanup' );
	}

	public static function resource_url(): string { return rest_url( 'kodanote-mcp/v1/mcp' ); }
	public static function issuer_url(): string { return untrailingslashit( home_url( '/' ) ); }
	public static function oauth_url( string $path ): string { return rest_url( 'kodanote-mcp/v1/oauth/' . $path ); }
	public static function resource_metadata_url(): string { return self::oauth_url( 'resource-metadata' ); }
	public static function scopes(): array { return array_keys( Access::scopes() ); }
	public static function secure(): bool {
		return ( is_ssl() && 'https' === wp_parse_url( self::resource_url(), PHP_URL_SCHEME ) ) ||
			( defined( 'KODANOTE_MCP_ALLOW_HTTP' ) && KODANOTE_MCP_ALLOW_HTTP && in_array( wp_get_environment_type(), array( 'local', 'development' ), true ) );
	}

	/** RFC 8414 / 9728 root and path-qualified discovery; web server must route these to WP. */
	public static function discovery(): void {
		$path = wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ?? '' ), PHP_URL_PATH );
		$site_path = rtrim( (string) wp_parse_url( self::issuer_url(), PHP_URL_PATH ), '/' );
		$resource_path = (string) wp_parse_url( self::resource_url(), PHP_URL_PATH );
		$auth_paths = array( '/.well-known/oauth-authorization-server' . $site_path, $site_path . '/.well-known/oauth-authorization-server' );
		$resource_paths = array( '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource' . $resource_path, $site_path . '/.well-known/oauth-protected-resource' );
		if ( in_array( $path, $auth_paths, true ) ) { $data = OAuth::metadata(); }
		elseif ( in_array( $path, $resource_paths, true ) ) { $data = OAuth::resource_metadata(); }
		else { return; }
		header( 'Access-Control-Allow-Origin: *' );
		header( 'Cache-Control: no-store' );
		if ( ! in_array( $_SERVER['REQUEST_METHOD'] ?? 'GET', array( 'GET', 'HEAD', 'OPTIONS' ), true ) ) {
			header( 'Allow: GET, HEAD, OPTIONS' ); wp_send_json( array( 'error' => 'invalid_request' ), 405 );
		}
		if ( ! self::secure() ) { wp_send_json( array( 'error' => 'HTTPS is required.' ), 503 ); }
		wp_send_json( $data );
	}
}
