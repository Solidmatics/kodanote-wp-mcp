<?php
/** Isolated transport regression tests. Run with: php tests/transport.php */

namespace {
	define( 'ABSPATH', __DIR__ );
	define( 'KODANOTE_MCP_VERSION', '0.1.0' );
	$GLOBALS['test_user'] = 99;
	$GLOBALS['test_filters'] = array();
	$GLOBALS['test_schema_calls'] = 0;

	class WP_Error {
		private $code;
		private $message;
		private $data;
		public function __construct( $code, $message, $data = null ) { $this->code = $code; $this->message = $message; $this->data = $data; }
		public function get_error_message() { return $this->message; }
		public function get_error_data() { return $this->data; }
	}
	class WP_REST_Request {
		public $headers = array();
		public $body = '';
		private $method;
		private $route;
		public function __construct( $method = 'POST', $route = '/kodanote-mcp/v1/mcp' ) { $this->method = $method; $this->route = $route; }
		public function get_method() { return $this->method; }
		public function get_route() { return $this->route; }
		public function get_header( $name ) { return $this->headers[ strtolower( $name ) ] ?? null; }
		public function get_body() { return $this->body; }
	}
	class WP_REST_Response {
		private $data;
		private $status;
		private $headers = array();
		public function __construct( $data = null, $status = 200 ) { $this->data = $data; $this->status = $status; }
		public function get_data() { return $this->data; }
		public function get_status() { return $this->status; }
		public function get_headers() { return $this->headers; }
		public function header( $name, $value ) { $this->headers[ $name ] = $value; }
	}
	class Fake_HTTP_Server {
		public $headers = array( 'Access-Control-Allow-Origin' => 'https://attacker.test', 'Access-Control-Allow-Credentials' => 'true' );
		public function remove_header( $name ) { unset( $this->headers[ $name ] ); }
		public function send_header( $name, $value ) { $this->headers[ $name ] = $value; }
	}
	function is_wp_error( $value ) { return $value instanceof WP_Error; }
	function get_current_user_id() { return $GLOBALS['test_user']; }
	function wp_set_current_user( $id ) { $GLOBALS['test_user'] = $id; }
	function wp_parse_url( $url ) { return parse_url( $url ); }
	function wp_json_encode( $data, $flags = 0 ) { return json_encode( $data, $flags ); }
	function apply_filters( $name, $value ) { return isset( $GLOBALS['test_filters'][ $name ] ) ? $GLOBALS['test_filters'][ $name ]( $value ) : $value; }
	function add_filter( $name, $callback, $priority = 10, $argc = 1 ) { $GLOBALS['registered_filters'][ $name ] = array( $callback, $priority, $argc ); }
	function register_rest_route( $namespace, $route, $args ) { $GLOBALS['registered_route'] = array( $namespace, $route, $args ); }
	// A small seam records that WordPress schema validation is invoked; real schema
	// semantics are covered by the separate integration suite against WordPress.
	function rest_validate_value_from_schema( $value, $schema, $path = '' ) {
		++$GLOBALS['test_schema_calls'];
		foreach ( $schema['required'] ?? array() as $key ) {
			if ( ! array_key_exists( $key, $value ) ) { return new WP_Error( 'required', 'Missing required property ' . $key ); }
		}
		return true;
	}
}

namespace Kodanote\MCP {
	// Audit persistence/restore behavior is covered against real WordPress in the HTTP suite.
	class Audit {
		public static function execute( $name, $args, $grant ) { return Tools::call( $name, $args ); }
	}
	class Plugin {
		public static function resource_url(): string { return 'https://wordpress.test/wp-json/kodanote-mcp/v1/mcp'; }
		public static function resource_metadata_url(): string { return 'https://wordpress.test/.well-known/oauth-protected-resource'; }
	}
	class OAuth {
		public static $calls = 0;
		public static $scope = 'content:read content:write';
		public static $failure;
		public static function authenticate( $request ) {
			++self::$calls;
			if ( self::$failure ) { return self::$failure; }
			return 'Bearer valid' === $request->get_header( 'authorization' ) ? array( 'user_id' => 17, 'scope' => self::$scope ) : new \WP_Error( 'unauthorized', 'Denied', array( 'status' => 401 ) );
		}
	}
	class Tools {
		public static $calls = 0;
		public static $denied = array();
		public static function definitions(): array {
			return array_map( static function ( $name ) {
				return array( 'name' => $name, 'title' => $name, 'inputSchema' => array(
					'type' => 'object', 'additionalProperties' => false, 'required' => array( 'id' ),
					'properties' => array(
						'id' => array( 'type' => 'integer' ),
						'seo' => array( 'type' => 'object', 'additionalProperties' => false, 'properties' => array( 'title' => array( 'type' => 'string' ) ) ),
						'tags' => array( 'type' => 'array', 'items' => array( 'type' => 'integer' ) ),
					),
				) );
			}, array( 'read_tool', 'write_tool', 'fail_tool', 'throw_tool' ) );
		}
		public static function required_scope( $name ): ?string { return 'write_tool' === $name ? 'content:write' : 'content:read'; }
		public static function can_use( $name ): bool { return ! in_array( $name, self::$denied, true ); }
		public static function call( $name, $args ) {
			++self::$calls;
			if ( 'fail_tool' === $name ) { return new \WP_Error( 'failed', 'Permission denied.' ); }
			if ( 'throw_tool' === $name ) { throw new \RuntimeException( 'Secret database password must never be exposed' ); }
			return array( 'current_user' => \get_current_user_id(), 'arguments' => $args );
		}
	}
}

namespace {
	require dirname( __DIR__ ) . '/includes/class-server.php';
	use Kodanote\MCP\Server;
	use Kodanote\MCP\OAuth;
	use Kodanote\MCP\Tools;

	$checks = 0;
	function check( $condition, $message ) {
		++$GLOBALS['checks'];
		if ( ! $condition ) { throw new RuntimeException( $message ); }
	}
	function request( $message, $headers = array(), $method = 'POST' ) {
		$request = new WP_REST_Request( $method );
		$request->headers = array_merge( array( 'content-type' => 'application/json', 'accept' => 'application/json, text/event-stream', 'authorization' => 'Bearer valid', 'mcp-protocol-version' => '2025-11-25' ), $headers );
		$request->body = is_string( $message ) ? $message : json_encode( $message );
		return $request;
	}
	function rpc( $method, $params = null, $id = 1 ) {
		$message = array( 'jsonrpc' => '2.0', 'id' => $id, 'method' => $method );
		if ( null !== $params ) { $message['params'] = (object) $params; }
		return $message;
	}
	function call( $args, $name = 'read_tool' ) { return rpc( 'tools/call', array( 'name' => $name, 'arguments' => $args ) ); }
	function error_code( $response ) { return $response->get_data()['error']['code'] ?? null; }

	Server::register_routes();
	check( 'kodanote-mcp/v1' === $GLOBALS['registered_route'][0], 'MCP route registered' );
	check( 5 === $GLOBALS['registered_filters']['rest_pre_dispatch'][1], 'MCP runs before WordPress automatic OPTIONS and JSON parsing' );
	$initialize = rpc( 'initialize', array( 'protocolVersion' => '2025-11-25', 'capabilities' => (object) array(), 'clientInfo' => (object) array( 'name' => 'test', 'version' => '1' ) ) );
	$response = Server::handle( request( $initialize ) );
	check( 200 === $response->get_status() && '2025-11-25' === $response->get_data()['result']['protocolVersion'], 'Initialization negotiates supported protocol' );
	check( 99 === get_current_user_id(), 'Initialization restores original WordPress user' );
	check( ! isset( $response->get_headers()['MCP-Session-Id'] ), 'Transport remains stateless' );
	$initialize['params']->protocolVersion = 'future-version';
	check( '2025-11-25' === Server::handle( request( $initialize ) )->get_data()['result']['protocolVersion'], 'Unsupported initialization offers supported protocol' );
	check( -32602 === error_code( Server::handle( request( rpc( 'initialize', array() ) ) ) ), 'Invalid initialize parameters rejected' );
	$response = Server::handle( request( rpc( 'ping' ), array( 'mcp-protocol-version' => null ) ) );
	check( '2025-03-26' === $response->get_headers()['MCP-Protocol-Version'], 'Absent header uses backward-compatible protocol' );
	check( $response->get_data()['result'] instanceof stdClass, 'Ping returns empty object, not array' );
	check( 400 === Server::handle( request( rpc( 'ping' ), array( 'mcp-protocol-version' => '2024-11-05' ) ) )->get_status(), 'Invalid header protocol rejected' );
	check( 406 === Server::handle( request( rpc( 'ping' ), array( 'accept' => 'application/json' ) ) )->get_status(), 'Accept must include both transport formats' );
	check( 406 === Server::handle( request( rpc( 'ping' ), array( 'accept' => 'application/json, text/event-stream;q=0' ) ) )->get_status(), 'A disabled SSE media type does not satisfy Accept' );
	check( 415 === Server::handle( request( rpc( 'ping' ), array( 'content-type' => 'text/plain' ) ) )->get_status(), 'Non-JSON body type rejected' );
	check( 413 === Server::handle( request( str_repeat( ' ', 1048577 ) ) )->get_status(), 'Oversized request rejected' );
	check( -32700 === error_code( Server::handle( request( '{invalid' ) ) ), 'Malformed JSON yields parse error' );
	check( -32600 === error_code( Server::handle( request( '[{"jsonrpc":"2.0","method":"ping","id":1}]' ) ) ), 'Batch requests rejected' );
	foreach ( array( null, false, 1.5, array() ) as $id ) {
		check( -32600 === error_code( Server::handle( request( rpc( 'ping', null, $id ) ) ) ), 'Invalid request id rejected' );
	}
	check( -32602 === error_code( Server::handle( request( '{"jsonrpc":"2.0","method":"ping","id":1,"params":[]}' ) ) ), 'Array params rejected' );
	check( -32602 === error_code( Server::handle( request( rpc( 'ping', array( '_meta' => null ) ) ) ) ), 'Invalid metadata rejected' );
	check( -32601 === error_code( Server::handle( request( rpc( 'unknown_method' ) ) ) ), 'Unknown method rejected' );
	check( -32602 === error_code( Server::handle( request( rpc( 'tools/list', array( 'cursor' => 'bad' ) ) ) ) ), 'Unknown pagination cursor rejected' );
	foreach ( array( 'notifications/initialized', 'notifications/cancelled' ) as $method ) {
		$message = array( 'jsonrpc' => '2.0', 'method' => $method, 'params' => (object) ( 'notifications/cancelled' === $method ? array( 'requestId' => 1 ) : array() ) );
		$response = Server::handle( request( $message ) );
		check( 202 === $response->get_status() && null === $response->get_data(), 'Supported notification acknowledged without body' );
	}
	$message = call( (object) array( 'id' => 1 ), 'write_tool' );
	unset( $message['id'] );
	$calls = Tools::$calls;
	check( 400 === Server::handle( request( $message ) )->get_status() && $calls === Tools::$calls, 'Tool notification cannot cause side effects' );
	$response = Server::handle( request( call( (object) array( 'id' => 1, 'seo' => (object) array( 'title' => 'Hi' ), 'tags' => array( 1, 2 ) ) ) ) );
	check( 17 === $response->get_data()['result']['structuredContent']->current_user && 99 === get_current_user_id(), 'Tool executes as OAuth user and original user restored' );
	check( 'text' === $response->get_data()['result']['content'][0]['type'] && false === $response->get_data()['result']['isError'], 'Tool result contains text and structured data' );
	check( $GLOBALS['test_schema_calls'] > 0, 'Delegates JSON Schema constraints to WordPress' );
	$response = Server::handle( request( call( (object) array( 'id' => 1 ) ), array( 'mcp-protocol-version' => '2025-03-26' ) ) );
	check( ! isset( $response->get_data()['result']['structuredContent'] ), 'Old protocol retains compatible text result' );
	foreach ( array( array(), (object) array(), (object) array( 'id' => '1' ), (object) array( 'id' => true ), (object) array( 'id' => 1, 'unknown' => 1 ), (object) array( 'id' => 1, 'seo' => array() ), (object) array( 'id' => 1, 'seo' => (object) array( 'unknown' => 'x' ) ), (object) array( 'id' => 1, 'tags' => (object) array( 'zero' => 1 ) ), (object) array( 'id' => 1, 'tags' => array( '1' ) ) ) as $args ) {
		$calls = Tools::$calls;
		check( -32602 === error_code( Server::handle( request( call( $args ) ) ) ) && $calls === Tools::$calls, 'Invalid tool arguments cannot invoke tool' );
	}
	check( -32602 === error_code( Server::handle( request( call( (object) array( 'id' => 1 ), 'unknown' ) ) ) ), 'Unknown tool rejected' );
	$response = Server::handle( request( call( (object) array( 'id' => 1 ), 'fail_tool' ) ) );
	check( true === $response->get_data()['result']['isError'], 'Tool failures return model-visible isError result' );
	$response = Server::handle( request( call( (object) array( 'id' => 1 ), 'throw_tool' ) ) );
	check( 500 === $response->get_status() && 1 === $response->get_data()['id'] && -32603 === error_code( $response ) && false === strpos( json_encode( $response->get_data() ), 'password' ) && 99 === get_current_user_id(), 'Exceptions preserve request id, hide secrets, and restore WordPress user' );
	OAuth::$scope = 'content:read';
	$response = Server::handle( request( rpc( 'tools/list' ) ) );
	check( 3 === count( $response->get_data()['result']['tools'] ), 'Read grant does not advertise write tools' );
	$calls = Tools::$calls;
	$response = Server::handle( request( call( (object) array( 'id' => 1 ), 'write_tool' ) ) );
	check( 403 === $response->get_status() && false !== strpos( $response->get_headers()['WWW-Authenticate'], 'scope="content:write"' ) && $calls === Tools::$calls, 'Read grant cannot invoke write tool and challenge names required scope' );
	OAuth::$scope = 'content:read content:write';
	Tools::$denied = array( 'write_tool' );
	$response = Server::handle( request( rpc( 'tools/list' ) ) );
	$names = array_column( $response->get_data()['result']['tools'], 'name' );
	check( ! in_array( 'write_tool', $names, true ) && in_array( 'read_tool', $names, true ), 'Discovery hides tools unavailable to the WordPress user despite token scope' );
	$calls = Tools::$calls;
	$response = Server::handle( request( call( (object) array( 'id' => 1 ), 'write_tool' ) ) );
	check( $calls === Tools::$calls && ( isset( $response->get_data()['error'] ) || ! empty( $response->get_data()['result']['isError'] ) ), 'Crafted tool calls cannot bypass WordPress capability checks' );
	Tools::$denied = array();
	foreach ( array( 'GET', 'DELETE', 'PUT', 'HEAD' ) as $method ) {
		check( 401 === Server::handle( request( '', array( 'authorization' => null ), $method ) )->get_status(), 'Authentication required for every method except preflight' );
		check( 405 === Server::handle( request( '', array(), $method ) )->get_status(), 'Authenticated unsupported method returns 405' );
	}
	$response = Server::handle( request( rpc( 'ping' ), array( 'authorization' => null ) ) );
	check( false !== strpos( $response->get_headers()['WWW-Authenticate'], 'resource_metadata=' ), '401 exposes OAuth resource discovery' );
	check( false === strpos( $response->get_headers()['WWW-Authenticate'], 'invalid_token' ), 'Missing token challenge does not incorrectly identify invalid token' );
	$response = Server::handle( request( rpc( 'ping' ), array( 'authorization' => 'Bearer bad' ) ) );
	check( false !== strpos( $response->get_headers()['WWW-Authenticate'], 'invalid_token' ), 'Invalid token challenge identifies error' );
	OAuth::$failure = new WP_Error( 'https_required', 'HTTPS is required.', array( 'status' => 503 ) );
	$response = Server::handle( request( rpc( 'ping' ) ) );
	check( 503 === $response->get_status() && ! isset( $response->get_headers()['WWW-Authenticate'] ), 'OAuth service errors preserve status without invalid-token challenge' );
	OAuth::$failure = null;
	foreach ( array( 'https://attacker.test', 'null', 'https://claude.ai.attacker.test', 'https://claude.ai/path', 'https://claude.ai?x=1', "https://claude.ai\r\nX-Fake: yes" ) as $origin ) {
		$auth_calls = OAuth::$calls;
		check( 403 === Server::handle( request( rpc( 'ping' ), array( 'origin' => $origin ) ) )->get_status(), 'Untrusted or malformed Origin rejected' );
		check( 403 === Server::handle( request( '', array( 'origin' => $origin ), 'OPTIONS' ) )->get_status() && OAuth::$calls === $auth_calls, 'Untrusted preflight rejected before OAuth' );
	}
	foreach ( array( 'https://claude.ai', 'https://wordpress.test', 'https://wordpress.test:443' ) as $origin ) {
		$response = Server::handle( request( rpc( 'ping' ), array( 'origin' => $origin ) ) );
		check( 200 === $response->get_status() && $origin === $response->get_headers()['Access-Control-Allow-Origin'] && ! isset( $response->get_headers()['Access-Control-Allow-Credentials'] ), 'Trusted CORS origin is explicit without cookie credentials' );
	}
	$auth_calls = OAuth::$calls;
	$response = Server::handle( request( '', array( 'origin' => 'https://claude.ai', 'authorization' => null ), 'OPTIONS' ) );
	check( 204 === $response->get_status() && OAuth::$calls === $auth_calls, 'Trusted preflight does not require bearer token' );
	$GLOBALS['test_filters']['kodanote_mcp_allowed_origins'] = static function ( $origins ) { $origins[] = 'https://custom-client.test'; return $origins; };
	check( 200 === Server::handle( request( rpc( 'ping' ), array( 'origin' => 'https://custom-client.test' ) ) )->get_status(), 'Site owner may configure additional client origin' );
	$server = new Fake_HTTP_Server();
	Server::serve_headers( false, new WP_REST_Response( null, 403 ), request( '', array( 'origin' => 'https://attacker.test' ) ), $server );
	check( ! isset( $server->headers['Access-Control-Allow-Origin'], $server->headers['Access-Control-Allow-Credentials'] ), 'Final serve hook removes WordPress permissive CORS on rejected origins' );
	$server = new Fake_HTTP_Server();
	check( true === Server::serve_headers( false, new WP_REST_Response( null, 202 ), request( '' ), $server ), 'Notification acknowledgement suppresses actual response body' );
	$unrelated = new WP_REST_Request( 'GET', '/wp/v2/posts' );
	$server = new Fake_HTTP_Server();
	check( false === Server::serve_headers( false, new WP_REST_Response(), $unrelated, $server ) && isset( $server->headers['Access-Control-Allow-Credentials'] ), 'Unrelated WordPress route is unchanged' );
	check( null === Server::pre_dispatch( null, null, $unrelated ), 'Unrelated route bypasses MCP interception' );
	fwrite( STDOUT, "Transport: {$checks} assertions passed.\n" );
}
