<?php
namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

/** Authorization-code OAuth with mandatory S256 PKCE and resource-bound opaque tokens. */
final class OAuth {
	public const ACCESS_TTL = 3600;
	public const GRANT_TTL = 2592000;

	public static function register_routes(): void {
		foreach ( array( 'metadata', 'resource-metadata', 'register', 'token', 'revoke' ) as $route ) {
			$callback = str_replace( '-', '_', $route );
			register_rest_route( 'kodanote-mcp/v1', '/oauth/' . $route, array(
				'methods' => in_array( $route, array( 'metadata', 'resource-metadata' ), true ) ? 'GET' : 'POST',
				'permission_callback' => '__return_true',
				'callback' => static function ( \WP_REST_Request $request ) use ( $callback ) {
					if ( ! Plugin::secure() ) { return self::error( 'temporarily_unavailable', 'HTTPS is required.', 503 ); }
					if ( strlen( $request->get_body() ) > 16384 ) { return self::error( 'invalid_request', 'Request too large.', 413 ); }
					if ( in_array( $callback, array( 'metadata', 'resource_metadata' ), true ) ) { return self::response( self::$callback() ); }
					return self::$callback( $request );
				},
			) );
		}
		// OAuth public clients can run in browsers. Never expose WordPress cookie credentials.
		add_filter( 'rest_pre_serve_request', static function ( $served, $result, $request ) {
			if ( str_starts_with( $request->get_route(), '/kodanote-mcp/v1/oauth/' ) ) {
				header_remove( 'Access-Control-Allow-Credentials' );
				header( 'Access-Control-Allow-Origin: *' );
				header( 'Access-Control-Allow-Headers: Authorization, Content-Type' );
				header( 'Access-Control-Allow-Methods: GET, POST, OPTIONS' );
				header( 'Cache-Control: no-store' );
			}
			return $served;
		}, PHP_INT_MAX, 3 );
	}

	public static function metadata(): array {
		return array(
			'issuer' => Plugin::issuer_url(),
			'authorization_endpoint' => admin_url( 'admin-post.php?action=kodanote_mcp_authorize' ),
			'token_endpoint' => Plugin::oauth_url( 'token' ),
			'registration_endpoint' => Plugin::oauth_url( 'register' ),
			'revocation_endpoint' => Plugin::oauth_url( 'revoke' ),
			'response_types_supported' => array( 'code' ),
			'grant_types_supported' => array( 'authorization_code', 'refresh_token' ),
			'token_endpoint_auth_methods_supported' => array( 'none', 'client_secret_post', 'client_secret_basic' ),
			'revocation_endpoint_auth_methods_supported' => array( 'none', 'client_secret_post', 'client_secret_basic' ),
			'code_challenge_methods_supported' => array( 'S256' ),
			'scopes_supported' => Plugin::scopes(),
		);
	}

	public static function resource_metadata(): array {
		return array(
			'resource' => Plugin::resource_url(),
			'authorization_servers' => array( Plugin::issuer_url() ),
			'bearer_methods_supported' => array( 'header' ),
			'scopes_supported' => Plugin::scopes(),
			'resource_name' => get_bloginfo( 'name' ) . ' — Kodanote MCP',
		);
	}

	public static function random(): string { return rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' ); }
	private static function string( array $params, string $key, string $default = '' ): string {
		return isset( $params[ $key ] ) && is_string( $params[ $key ] ) ? $params[ $key ] : $default;
	}
	private static function response( array $data, int $status = 200 ): \WP_REST_Response {
		return new \WP_REST_Response( $data, $status, array( 'Cache-Control' => 'no-store', 'Pragma' => 'no-cache' ) );
	}
	private static function error( string $code, string $description, int $status = 400 ): \WP_REST_Response {
		$response = self::response( array( 'error' => $code, 'error_description' => $description ), $status );
		if ( 401 === $status ) { $response->header( 'WWW-Authenticate', 'Basic realm="Kodanote MCP OAuth"' ); }
		if ( 429 === $status ) { $response->header( 'Retry-After', '3600' ); }
		return $response;
	}
	private static function throttled( string $action, int $limit ): bool {
		// REMOTE_ADDR is trusted; arbitrary Forwarded/X-Forwarded-For headers are not.
		return ! Store::rate_limit( $action . ':' . ( $_SERVER['REMOTE_ADDR'] ?? 'unknown' ), $limit, 3600 );
	}

	public static function valid_redirect( $uri ): bool {
		if ( ! is_string( $uri ) || strlen( $uri ) > 2048 || preg_match( '/[\x00-\x20\x7f\\\\]/', $uri ) ) { return false; }
		$p = wp_parse_url( $uri );
		if ( ! is_array( $p ) || empty( $p['host'] ) || isset( $p['fragment'] ) || isset( $p['user'] ) || isset( $p['pass'] ) ) { return false; }
		if ( str_contains( $p['host'], '*' ) ) { return false; }
		return 'https' === ( $p['scheme'] ?? '' ) || ( 'http' === ( $p['scheme'] ?? '' ) && in_array( $p['host'], array( '127.0.0.1', '[::1]', 'localhost' ), true ) );
	}

	public static function register( \WP_REST_Request $request ): \WP_REST_Response {
		if ( self::throttled( 'register', 20 ) || ! Store::rate_limit( 'register:global', 1000, DAY_IN_SECONDS ) ) { return self::error( 'slow_down', 'Registration limit reached. Try again later.', 429 ); }
		if ( ! $request->is_json_content_type() ) { return self::error( 'invalid_client_metadata', 'Send a JSON object.' ); }
		$p = $request->get_json_params();
		if ( ! is_array( $p ) ) { return self::error( 'invalid_client_metadata', 'Send a JSON object.' ); }
		foreach ( array( 'client_name', 'scope', 'token_endpoint_auth_method' ) as $field ) {
			if ( array_key_exists( $field, $p ) && ! is_string( $p[ $field ] ) ) { return self::error( 'invalid_client_metadata', $field . ' must be a string.' ); }
		}
		$redirects = $p['redirect_uris'] ?? null;
		if ( ! is_array( $redirects ) || ! array_is_list( $redirects ) || count( $redirects ) < 1 || count( $redirects ) > 10 ) { return self::error( 'invalid_redirect_uri', 'Provide 1–10 exact redirect URIs.' ); }
		foreach ( $redirects as $uri ) { if ( ! self::valid_redirect( $uri ) ) { return self::error( 'invalid_redirect_uri', 'Use HTTPS redirects or HTTP loopback redirects, without fragments or credentials.' ); } }
		$method = self::string( $p, 'token_endpoint_auth_method', 'client_secret_basic' );
		if ( ! in_array( $method, array( 'none', 'client_secret_post', 'client_secret_basic' ), true ) ) { return self::error( 'invalid_client_metadata', 'Unsupported client authentication method.' ); }
		$grants = $p['grant_types'] ?? array( 'authorization_code' );
		if ( ! is_array( $grants ) || ! array_is_list( $grants ) || count( array_filter( $grants, 'is_string' ) ) !== count( $grants ) || ! in_array( 'authorization_code', $grants, true ) || array_diff( $grants, array( 'authorization_code', 'refresh_token' ) ) ) { return self::error( 'invalid_client_metadata', 'Only authorization_code and refresh_token grants are supported.' ); }
		if ( isset( $p['response_types'] ) && array( 'code' ) !== $p['response_types'] ) { return self::error( 'invalid_client_metadata', 'Only the code response type is supported.' ); }
		$scope = self::scope( self::string( $p, 'scope', implode( ' ', Plugin::scopes() ) ) );
		if ( null === $scope ) { return self::error( 'invalid_client_metadata', 'Unknown scope.' ); }
		$id = self::random();
		$secret = 'none' === $method ? '' : self::random();
		$client = array(
			'client_id' => $id, 'client_id_issued_at' => time(),
			'client_name' => mb_substr( sanitize_text_field( self::string( $p, 'client_name', 'MCP client' ) ), 0, 120 ),
			'redirect_uris' => array_values( array_unique( $redirects ) ),
			'token_endpoint_auth_method' => $method, 'grant_types' => $grants,
			'response_types' => array( 'code' ), 'scope' => $scope,
		);
		$stored = $client;
		$stored['secret_hash'] = $secret ? hash( 'sha256', $secret ) : '';
		if ( ! Store::put( 'client', $id, $stored, time() + YEAR_IN_SECONDS ) ) { return self::error( 'server_error', 'Could not register client.', 500 ); }
		if ( $secret ) { $client['client_secret'] = $secret; $client['client_secret_expires_at'] = 0; }
		return self::response( $client, 201 );
	}

	private static function scope( string $scope ): ?string {
		return Access::normalize( $scope );
	}

	/** Browser-only login and explicit, nonce-protected consent. OAuth values stay server-side on POST. */
	public static function authorize(): void {
		nocache_headers();
		header( 'Referrer-Policy: no-referrer' );
		header( "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" );
		header( 'X-Frame-Options: DENY' );
		if ( ! Plugin::secure() ) { self::stop( 'HTTPS is required.', 503 ); }
		$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
		if ( ! in_array( $method, array( 'GET', 'POST' ), true ) ) { self::stop( 'Method not allowed.', 405 ); }
		if ( 'POST' === $method ) {
			$p = wp_unslash( $_POST );
			$id = self::string( $p, 'pending' );
			$pending = Store::get( 'consent', $id );
			if ( ! is_user_logged_in() || ! $pending || $pending['_consumed'] || (int) $pending['user_id'] !== get_current_user_id() || ! hash_equals( $pending['session'], hash( 'sha256', wp_get_session_token() ) ) || ! wp_verify_nonce( self::string( $p, '_wpnonce' ), 'kodanote_mcp_consent_' . $id ) ) { self::stop( 'This consent request expired. Start connecting again.', 403 ); }
			if ( ! Store::consume( 'consent', $id ) ) { self::stop( 'This request was already used.', 403 ); }
			if ( ! self::eligible( get_current_user_id() ) ) { self::stop( 'Your WordPress account has no available MCP permissions.', 403 ); }
			$decision = self::string( $p, 'decision' );
			if ( ! in_array( $decision, array( 'allow', 'read' ), true ) ) { self::redirect( $pending, array( 'error' => 'access_denied', 'error_description' => 'The user declined access.' ) ); }
			$scope = $pending['scope'];
			if ( '1' === self::string( $p, 'scope_selection' ) ) {
				$selected = array_filter( explode( ' ', $scope ), static function ( $item ) use ( $p ) { return '1' === self::string( $p, Access::field_name( $item ) ); } );
				$scope = Access::normalize( implode( ' ', $selected ) ) ?? '';
				$scope = implode( ' ', array_intersect( explode( ' ', $scope ), explode( ' ', $pending['scope'] ) ) );
			}
			if ( 'read' === $decision ) { $scope = Access::read_only( $scope ); }
			$pending['scope'] = Access::permitted( $scope );
			if ( '' === $pending['scope'] ) { self::redirect( $pending, array( 'error' => 'access_denied', 'error_description' => 'No available permissions were selected.' ) ); }
			$code = self::random();
			$pending['grant_id'] = self::random();
			unset( $pending['_consumed'], $pending['_expires'], $pending['session'] );
			if ( ! Store::put( 'code', $code, $pending, time() + 300 ) ) { self::stop( 'Could not issue authorization code.', 500 ); }
			self::redirect( $pending, array( 'code' => $code ) );
		}
		$p = wp_unslash( $_GET );
		$client_id = self::string( $p, 'client_id' );
		$client = Store::get( 'client', $client_id );
		$redirect = self::string( $p, 'redirect_uri' );
		// Never redirect any error until both the client and the exact redirect are validated.
		if ( ! $client || ! in_array( $redirect, $client['redirect_uris'], true ) ) { self::stop( 'Unknown client or invalid redirect URI.', 400 ); }
		$pending = array( 'client_id' => $client_id, 'redirect_uri' => $redirect, 'state' => self::string( $p, 'state' ) );
		if ( strlen( $pending['state'] ) > 2048 ) { self::stop( 'State is too long.', 400 ); }
		if ( 'code' !== self::string( $p, 'response_type' ) ) { self::redirect( $pending, array( 'error' => 'unsupported_response_type' ) ); }
		if ( Plugin::resource_url() !== self::string( $p, 'resource' ) ) { self::redirect( $pending, array( 'error' => 'invalid_target', 'error_description' => 'Use the exact MCP endpoint as resource.' ) ); }
		$scope = self::scope( self::string( $p, 'scope', $client['scope'] ) );
		if ( null === $scope || array_diff( explode( ' ', $scope ), explode( ' ', $client['scope'] ) ) ) { self::redirect( $pending, array( 'error' => 'invalid_scope' ) ); }
		$challenge = self::string( $p, 'code_challenge' );
		if ( 'S256' !== self::string( $p, 'code_challenge_method' ) || ! preg_match( '/^[A-Za-z0-9_-]{43}$/D', $challenge ) ) { self::redirect( $pending, array( 'error' => 'invalid_request', 'error_description' => 'S256 PKCE is required.' ) ); }
		if ( ! is_user_logged_in() ) {
			$query = array_intersect_key( $p, array_flip( array( 'client_id', 'redirect_uri', 'state', 'response_type', 'resource', 'scope', 'code_challenge', 'code_challenge_method' ) ) );
			wp_safe_redirect( wp_login_url( add_query_arg( $query, admin_url( 'admin-post.php?action=kodanote_mcp_authorize' ) ) ) ); exit;
		}
		if ( ! self::eligible( get_current_user_id() ) ) { self::stop( 'Your WordPress account has no available MCP permissions.', 403 ); }
		$scope = Access::permitted( $scope );
		if ( '' === $scope ) { self::redirect( $pending, array( 'error' => 'access_denied', 'error_description' => 'Your WordPress account cannot grant the requested permissions.' ) ); }
		if ( self::throttled( 'consent', 100 ) ) { self::stop( 'Too many connection requests. Try again later.', 429 ); }
		$pending += array( 'scope' => $scope, 'resource' => Plugin::resource_url(), 'challenge' => $challenge, 'user_id' => get_current_user_id(), 'session' => hash( 'sha256', wp_get_session_token() ) );
		$id = self::random();
		if ( ! Store::put( 'consent', $id, $pending, time() + 600 ) ) { self::stop( 'Could not start consent.', 500 ); }
		self::consent_page( $client, $pending, $id );
	}

	private static function stop( string $message, int $status ): void { wp_die( esc_html( $message ), 'Kodanote MCP', array( 'response' => $status ) ); }
	private static function redirect( array $pending, array $params ): void {
		if ( '' !== $pending['state'] ) { $params['state'] = $pending['state']; }
		// External redirect is intentional; exact URI was matched against client registration.
		wp_redirect( add_query_arg( $params, $pending['redirect_uri'] ), 302, 'Kodanote MCP' ); exit;
	}
	private static function consent_page( array $client, array $pending, string $id ): void {
		$requested = explode( ' ', $pending['scope'] );
		$definitions = Access::scopes();
		$write = Access::read_only( $pending['scope'] ) !== $pending['scope'];
		header( 'Content-Type: text/html; charset=UTF-8' );
		?><!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect to <?php echo esc_html( get_bloginfo( 'name' ) ); ?></title>
		<style>body{font:17px/1.6 system-ui;background:#f0f0f1;color:#1d2327;padding:5vh 20px}main{max-width:640px;margin:auto;padding:32px;background:white;border:1px solid #ddd;border-radius:12px}h1{line-height:1.2}code{overflow-wrap:anywhere}button{padding:10px 16px;margin:8px 8px 0 0;cursor:pointer}small{color:#50575e}</style><main>
		<h1>Connect <?php echo esc_html( $client['client_name'] ); ?></h1>
		<p>You are signed in to <strong><?php echo esc_html( get_bloginfo( 'name' ) ); ?></strong> as <?php echo esc_html( wp_get_current_user()->display_name ); ?>.</p>
		<p>Choose the permissions to delegate. Only permissions available to your WordPress account are shown. Each edit permission includes its corresponding read permission.</p>
		<p>Your WordPress permissions always apply. Access lasts up to 30 days, and you can revoke it from <strong>MCP Connections</strong> under Users or Profile.</p>
		<p><small>The application name is supplied by its developer and is not verified. Only approve an application you intended to connect. The authorization code will be sent to:</small><br><code><?php echo esc_html( $pending['redirect_uri'] ); ?></code></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php?action=kodanote_mcp_authorize' ) ); ?>">
		<input type="hidden" name="pending" value="<?php echo esc_attr( $id ); ?>"><?php wp_nonce_field( 'kodanote_mcp_consent_' . $id ); ?>
		<input type="hidden" name="scope_selection" value="1">
		<?php foreach ( $requested as $item ) : ?><p><label><input type="checkbox" name="<?php echo esc_attr( Access::field_name( $item ) ); ?>" value="1" checked> <strong><?php echo esc_html( $definitions[ $item ]['label'] ); ?></strong><br><small><?php echo esc_html( $definitions[ $item ]['description'] ); ?></small></label></p><?php endforeach; ?>
		<button type="submit" name="decision" value="allow">Allow selected access</button><?php if ( $write ) : ?><button type="submit" name="decision" value="read">Allow selected read access only</button><?php endif; ?><button type="submit" name="decision" value="deny">Cancel</button>
		</form></main></html><?php exit;
	}

	private static function client_auth( \WP_REST_Request $request, array $p ) {
		$id = self::string( $p, 'client_id' );
		$secret = self::string( $p, 'client_secret' );
		$method = '' !== $secret ? 'client_secret_post' : 'none';
		$header = (string) $request->get_header( 'authorization' );
		if ( '' !== $header ) {
			if ( ! preg_match( '/^Basic ([A-Za-z0-9+\/=]+)$/iD', $header, $m ) || false === ( $decoded = base64_decode( $m[1], true ) ) || ! str_contains( $decoded, ':' ) || '' !== $secret ) { return null; }
			list( $basic_id, $basic_secret ) = explode( ':', $decoded, 2 );
			$basic_id = urldecode( $basic_id );
			if ( '' !== $id && $id !== $basic_id ) { return null; }
			$id = $basic_id; $secret = urldecode( $basic_secret ); $method = 'client_secret_basic';
		}
		$client = Store::get( 'client', $id );
		if ( ! $client || $method !== $client['token_endpoint_auth_method'] ) { return null; }
		if ( 'none' !== $method && ! hash_equals( $client['secret_hash'], hash( 'sha256', $secret ) ) ) { return null; }
		return $client;
	}

	public static function token( \WP_REST_Request $request ): \WP_REST_Response {
		if ( self::throttled( 'token', 300 ) ) { return self::error( 'slow_down', 'Too many token requests.', 429 ); }
		if ( ! str_starts_with( strtolower( (string) $request->get_header( 'content-type' ) ), 'application/x-www-form-urlencoded' ) ) { return self::error( 'invalid_request', 'Use form-urlencoded parameters.' ); }
		$p = $request->get_body_params();
		$client = self::client_auth( $request, $p );
		if ( ! $client ) { return self::error( 'invalid_client', 'Client authentication failed.', 401 ); }
		$type = self::string( $p, 'grant_type' );
		if ( ! in_array( $type, $client['grant_types'], true ) ) { return self::error( 'unauthorized_client', 'Grant type is not registered for this client.' ); }
		if ( 'authorization_code' === $type ) {
			$code = self::string( $p, 'code' );
			$data = Store::get( 'code', $code );
			$verifier = self::string( $p, 'code_verifier' );
			if ( ! $data || $data['client_id'] !== $client['client_id'] || $data['redirect_uri'] !== self::string( $p, 'redirect_uri' ) || $data['resource'] !== self::string( $p, 'resource' ) || $data['resource'] !== Plugin::resource_url() || ! preg_match( '/^[A-Za-z0-9._~-]{43,128}$/D', $verifier ) || ! hash_equals( $data['challenge'], rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' ) ) ) { return self::error( 'invalid_grant', 'The code, client, redirect, resource or PKCE verifier is invalid.' ); }
			if ( $data['_consumed'] || ! Store::consume( 'code', $code ) ) { Store::revoke_grant( $data['grant_id'] ); return self::error( 'invalid_grant', 'Authorization code reuse detected. Reconnect to authorize again.' ); }
			if ( ! self::eligible( (int) $data['user_id'] ) ) { return self::error( 'invalid_grant', 'Authorization is no longer valid.' ); }
			$grant = array( 'id' => $data['grant_id'], 'client_id' => $client['client_id'], 'client_name' => $client['client_name'], 'user_id' => (int) $data['user_id'], 'scope' => $data['scope'], 'resource' => $data['resource'], 'created' => time(), 'expires' => time() + self::GRANT_TTL, 'user_stamp' => self::user_stamp( (int) $data['user_id'] ) );
			if ( ! Store::put( 'grant', $grant['id'], $grant, $grant['expires'] ) ) { return self::error( 'server_error', 'Could not create grant.', 500 ); }
			return self::issue( $grant, in_array( 'refresh_token', $client['grant_types'], true ) );
		}
		if ( 'refresh_token' !== $type ) { return self::error( 'unsupported_grant_type', 'Unsupported grant type.' ); }
		$refresh = self::string( $p, 'refresh_token' );
		$data = Store::get( 'refresh', $refresh );
		if ( ! $data || $data['client_id'] !== $client['client_id'] ) { return self::error( 'invalid_grant', 'Refresh token is invalid.' ); }
		$grant = self::valid_grant( $data['grant_id'] );
		if ( ! $grant ) { return self::error( 'invalid_grant', 'Authorization expired or was revoked.' ); }
		if ( isset( $p['resource'] ) && $grant['resource'] !== self::string( $p, 'resource' ) ) { return self::error( 'invalid_target', 'Resource does not match this grant.' ); }
		$scope = isset( $p['scope'] ) ? self::scope( self::string( $p, 'scope' ) ) : $data['scope'];
		if ( null === $scope || array_diff( explode( ' ', $scope ), explode( ' ', $data['scope'] ) ) ) { return self::error( 'invalid_scope', 'Refresh cannot increase permissions.' ); }
		if ( $data['_consumed'] || ! Store::consume( 'refresh', $refresh ) ) {
			Store::revoke_grant( $data['grant_id'] );
			return self::error( 'invalid_grant', 'Refresh token reuse detected. Reconnect to authorize again.' );
		}
		$grant['scope'] = $scope;
		return self::issue( $grant, true );
	}

	private static function issue( array $grant, bool $refresh ): \WP_REST_Response {
		$access = self::random(); $refresh_token = self::random();
		$data = array( 'grant_id' => $grant['id'], 'client_id' => $grant['client_id'], 'scope' => $grant['scope'] );
		$ttl = min( self::ACCESS_TTL, $grant['expires'] - time() );
		if ( $ttl <= 0 || ! Store::put( 'access', $access, $data, time() + $ttl ) || ( $refresh && ! Store::put( 'refresh', $refresh_token, $data, $grant['expires'] ) ) ) {
			Store::revoke_grant( $grant['id'] );
			return self::error( 'server_error', 'Could not issue tokens. Reconnect to authorize again.', 500 );
		}
		$result = array( 'access_token' => $access, 'token_type' => 'Bearer', 'expires_in' => $ttl, 'scope' => $grant['scope'] );
		if ( $refresh ) { $result['refresh_token'] = $refresh_token; }
		return self::response( $result );
	}

	private static function user_stamp( int $id ): string {
		$user = get_userdata( $id );
		return $user ? hash( 'sha256', $user->user_pass ) : '';
	}
	private static function eligible( int $id ): bool { return (bool) Access::available_scopes( $id ); }
	private static function valid_grant( string $id ): ?array {
		$grant = Store::get( 'grant', $id );
		if ( ! $grant || Store::get( 'revoked', $id ) || $grant['resource'] !== Plugin::resource_url() || ! self::eligible( (int) $grant['user_id'] ) || ! hash_equals( $grant['user_stamp'], self::user_stamp( (int) $grant['user_id'] ) ) ) { return null; }
		return $grant;
	}

	public static function authenticate( \WP_REST_Request $request ) {
		if ( ! Plugin::secure() ) { return new \WP_Error( 'https_required', 'HTTPS is required.', array( 'status' => 503 ) ); }
		$header = (string) $request->get_header( 'authorization' );
		if ( ! preg_match( '/^Bearer ([A-Za-z0-9_-]{43})$/iD', $header, $matches ) ) { return new \WP_Error( 'invalid_token', 'OAuth Bearer authorization is required.', array( 'status' => 401 ) ); }
		$token = Store::get( 'access', $matches[1] );
		$grant = $token ? self::valid_grant( $token['grant_id'] ) : null;
		if ( ! $grant ) { return new \WP_Error( 'invalid_token', 'The access token expired or was revoked.', array( 'status' => 401 ) ); }
		return array( 'user_id' => $grant['user_id'], 'scope' => Access::permitted( $token['scope'], (int) $grant['user_id'] ), 'grant_id' => $grant['id'], 'client_id' => $grant['client_id'] );
	}

	public static function revoke( \WP_REST_Request $request ): \WP_REST_Response {
		if ( self::throttled( 'revoke', 300 ) ) { return self::error( 'slow_down', 'Too many revocation requests.', 429 ); }
		if ( ! str_starts_with( strtolower( (string) $request->get_header( 'content-type' ) ), 'application/x-www-form-urlencoded' ) ) { return self::error( 'invalid_request', 'Use form-urlencoded parameters.' ); }
		$p = $request->get_body_params(); $client = self::client_auth( $request, $p );
		if ( ! $client ) { return self::error( 'invalid_client', 'Client authentication failed.', 401 ); }
		$token = self::string( $p, 'token' );
		foreach ( array( 'access', 'refresh' ) as $kind ) {
			$data = Store::get( $kind, $token );
			if ( $data && $data['client_id'] === $client['client_id'] ) { Store::revoke_grant( $data['grant_id'] ); }
		}
		return self::response( array() );
	}
}
