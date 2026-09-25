<?php
/** Reusable block navigation menus through the native WordPress REST controller. */

namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Navigation_Tools {

	public static function definitions(): array {
		$id = array( 'type' => 'integer', 'minimum' => 1 );
		$title = array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 1000 );
		$status = array( 'type' => 'string', 'enum' => array( 'draft', 'publish' ), 'description' => 'Only published menus render. Publishing may change the WordPress fallback used by navigation blocks with no selected ref.' );
		$content = array(
			'type' => 'string', 'maxLength' => 150000,
			'description' => 'Complete navigation INNER block markup, without an enclosing core/navigation block. Supports native links, nested submenus, page-list, home-link, search, social-links, spacer, site-title, site-logo, loginout and buttons. Maximum 250 blocks and 8 nesting levels. An empty string clears the menu; PHP, shortcode blocks, arbitrary HTML blocks and reusable block references are rejected.',
		);
		return array(
			self::definition( 'list_navigation', 'List block navigation menus', 'List reusable WordPress block navigation menus. Requires edit_theme_options. Does not list classic menu locations. Content is omitted; use get_navigation before editing. WordPress pagination totals precede per-item permission filtering.', array(
				'page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1 ),
				'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 50, 'default' => 20 ),
				'search' => array( 'type' => 'string', 'maxLength' => 200 ),
				'status' => array( 'type' => 'string', 'enum' => array( 'publish', 'draft', 'pending', 'private', 'any' ), 'default' => 'any' ),
			), array(), true ),
			self::definition( 'get_navigation', 'Get block navigation menu', 'Read navigation inner block markup and its current version. Use its ID as the ref attribute of a core/navigation block in a header, footer or template. Only published menus render on the site. Requires edit_theme_options and native permission to edit this menu.', array( 'id' => $id ), array( 'id' ), true ),
			self::definition( 'create_navigation', 'Create block navigation menu', 'Create a reusable WordPress block navigation menu, as a draft by default. Returns navigation_block markup for attaching it to a header, footer or template. Draft menus do not render; explicitly publish before attaching. Does not edit templates. Publishing may immediately change the WordPress fallback used by navigation blocks without a selected ref. Requires edit_theme_options and native create/publish permissions as applicable.', array( 'title' => $title, 'content' => $content, 'status' => array_merge( $status, array( 'default' => 'draft' ) ) ), array( 'title', 'content' ), false ),
			self::definition( 'update_navigation', 'Update block navigation menu', 'Update supplied title, complete navigation inner block markup or draft/publish status, preserving omitted fields. Changes to a published menu affect every place using it; publishing may change the fallback used by navigation blocks without a selected ref. Draft menus do not render. Requires edit_theme_options, native menu edit/publish permissions and the current version from get_navigation; stale versions fail without writing.', array(
				'id' => $id,
				'version' => array( 'type' => 'string', 'pattern' => '^[a-f0-9]{64}$', 'description' => 'The current version from get_navigation. Read again and review after a conflict.' ),
				'title' => $title, 'content' => $content, 'status' => $status,
			), array( 'id', 'version' ), false ),
		);
	}

	public static function required_scope( string $name ): ?string {
		if ( in_array( $name, array( 'list_navigation', 'get_navigation' ), true ) ) {
			return 'appearance:read';
		}
		return in_array( $name, array( 'create_navigation', 'update_navigation' ), true ) ? 'appearance:write' : null;
	}

	public static function can_use( string $name ): bool {
		if ( ! self::required_scope( $name ) || ! get_current_user_id() || ! current_user_can( 'read' ) || ! current_user_can( 'edit_theme_options' ) ) {
			return false;
		}
		$type = get_post_type_object( 'wp_navigation' );
		if ( ! $type || ! $type->show_in_rest || ! current_user_can( $type->cap->edit_posts ) ) {
			return false;
		}
		return 'create_navigation' !== $name || current_user_can( $type->cap->create_posts );
	}

	/** @return array|\WP_Error */
	public static function call( string $name, array $input ) {
		$definition = null;
		foreach ( self::definitions() as $candidate ) {
			if ( $name === $candidate['name'] ) {
				$definition = $candidate;
				break;
			}
		}
		if ( ! $definition ) {
			return self::error( 'unknown_tool', 'Unknown navigation tool.', 400 );
		}
		if ( ! self::can_use( $name ) ) {
			return self::error( 'forbidden', 'The connected WordPress user may not use this navigation tool.', 403 );
		}
		$valid = rest_validate_value_from_schema( $input, $definition['inputSchema'], 'arguments' );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		switch ( $name ) {
			case 'list_navigation':
				return self::list_navigation( $input );
			case 'get_navigation':
				return self::get_navigation( $input['id'] );
			case 'create_navigation':
				return self::create_navigation( $input );
			case 'update_navigation':
				return self::update_navigation( $input );
		}
		return self::error( 'unknown_tool', 'Unknown navigation tool.', 400 );
	}

	private static function list_navigation( array $input ) {
		$page = $input['page'] ?? 1;
		$response = self::request( 'GET', '/wp/v2/navigation', array(
			'context' => 'edit', '_fields' => self::fields(),
			'page' => $page, 'per_page' => $input['per_page'] ?? 20,
			'search' => $input['search'] ?? '', 'status' => $input['status'] ?? 'any',
			'orderby' => 'id', 'order' => 'asc',
		) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$items = array();
		foreach ( $response->get_data() as $item ) {
			if ( ! is_wp_error( self::editable_navigation( (int) $item['id'] ) ) ) {
				$items[] = self::format_navigation( $item, false );
			}
		}
		$headers = $response->get_headers();
		return array( 'items' => $items, 'page' => $page, 'total' => (int) ( $headers['X-WP-Total'] ?? 0 ), 'has_more' => $page < (int) ( $headers['X-WP-TotalPages'] ?? 0 ) );
	}

	private static function get_navigation( int $id ) {
		$post = self::editable_navigation( $id );
		if ( is_wp_error( $post ) ) {
			return $post;
		}
		$response = self::request( 'GET', '/wp/v2/navigation/' . $id, array( 'context' => 'edit', '_fields' => self::fields() ) );
		return is_wp_error( $response ) ? $response : self::format_navigation( $response->get_data(), true );
	}

	private static function create_navigation( array $input ) {
		$valid = self::validate_fields( $input );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		$response = self::request( 'POST', '/wp/v2/navigation', array(
			'context' => 'edit', '_fields' => self::fields(), 'status' => $input['status'] ?? 'draft',
			'title' => $input['title'], 'content' => $input['content'],
		) );
		return is_wp_error( $response ) ? $response : self::format_navigation( $response->get_data(), true );
	}

	private static function update_navigation( array $input ) {
		$current = self::get_navigation( $input['id'] );
		if ( is_wp_error( $current ) ) {
			return $current;
		}
		if ( ! hash_equals( $current['version'], $input['version'] ) ) {
			return self::error( 'version_conflict', 'The navigation menu changed after it was read. Read it again and reapply changes to the new version.', 409 );
		}
		$params = array_intersect_key( $input, array_flip( array( 'title', 'content', 'status' ) ) );
		if ( ! $params ) {
			return self::error( 'empty_update', 'Supply title, content or status to update.', 400 );
		}
		$valid = self::validate_fields( $params );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		$params['context'] = 'edit';
		$params['_fields'] = self::fields();
		$response = self::request( 'POST', '/wp/v2/navigation/' . $input['id'], $params );
		return is_wp_error( $response ) ? $response : self::format_navigation( $response->get_data(), true );
	}

	private static function editable_navigation( int $id ) {
		$post = get_post( $id );
		if ( ! $post || 'wp_navigation' !== $post->post_type || 'trash' === $post->post_status ) {
			return self::error( 'not_found', 'No accessible navigation menu with this ID.', 404 );
		}
		if ( ! current_user_can( 'read_post', $id ) || ! current_user_can( 'edit_post', $id ) ) {
			return self::error( 'forbidden', 'You may not read and edit this navigation menu.', 403 );
		}
		return $post;
	}

	private static function validate_fields( array $input ) {
		if ( isset( $input['title'] ) && '' === trim( sanitize_text_field( $input['title'] ) ) ) {
			return self::error( 'invalid_navigation_title', 'Menu titles must contain readable text.', 400 );
		}
		if ( ! array_key_exists( 'content', $input ) ) {
			return true;
		}
		$content = $input['content'];
		if ( false !== strpos( $content, '<?' ) || false !== strpos( $content, '?>' ) ) {
			return self::error( 'invalid_navigation_content', 'Navigation content must be native navigation block markup, not PHP.', 400 );
		}
		// The default block parser repairs malformed input. Check its tokens first so
		// an unclosed or mismatched submenu cannot silently change the intended tree.
		$parser = new \WP_Block_Parser();
		$parser->document = $content;
		$parser->offset = 0;
		$stack = array();
		$count = 0;
		while ( true ) {
			list( $kind, $name, $attrs, $start, $length ) = $parser->next_token();
			if ( 'no-more-tokens' === $kind ) {
				break;
			}
			$parser->offset = $start + $length;
			if ( 'block-closer' === $kind ) {
				if ( array_pop( $stack ) !== $name ) {
					return self::error( 'invalid_navigation_content', 'Navigation block opening and closing comments must match.', 400 );
				}
				continue;
			}
			if ( ! is_array( $attrs ) ) {
				return self::error( 'invalid_navigation_content', 'Navigation block attributes must contain valid JSON objects.', 400 );
			}
			++$count;
			if ( $count > 250 || count( $stack ) >= 8 ) {
				return self::error( 'invalid_navigation_content', 'Navigation menus support at most 250 blocks and 8 nesting levels.', 400 );
			}
			if ( 'block-opener' === $kind ) {
				$stack[] = $name;
			}
		}
		if ( $stack ) {
			return self::error( 'invalid_navigation_content', 'Every navigation block opening comment must have a matching closing comment.', 400 );
		}
		return self::validate_blocks( parse_blocks( $content ), 'core/navigation' );
	}

	private static function validate_blocks( array $blocks, string $parent ) {
		$menu_children = array( 'core/navigation-link', 'core/navigation-submenu', 'core/page-list', 'core/home-link', 'core/search', 'core/social-links', 'core/spacer', 'core/site-title', 'core/site-logo', 'core/loginout', 'core/buttons' );
		$children = array(
			'core/navigation' => $menu_children,
			'core/navigation-submenu' => array( 'core/navigation-link', 'core/navigation-submenu', 'core/page-list' ),
			'core/navigation-link' => array( 'core/navigation-link', 'core/navigation-submenu', 'core/page-list' ),
			'core/social-links' => array( 'core/social-link' ),
			'core/buttons' => array( 'core/button' ),
			'core/page-list' => array( 'core/page-list-item' ),
			'core/page-list-item' => array( 'core/page-list-item' ),
		);
		foreach ( $blocks as $block ) {
			$name = $block['blockName'];
			if ( null === $name && '' === trim( $block['innerHTML'] ?? '' ) ) {
				continue;
			}
			if ( ! in_array( $name, $children[ $parent ] ?? array(), true ) || ! \WP_Block_Type_Registry::get_instance()->is_registered( $name ) ) {
				return self::error( 'invalid_navigation_content', 'Use supported native navigation blocks in their proper parent blocks. Arbitrary HTML, shortcode blocks and reusable block references are not supported.', 400 );
			}
			$type = \WP_Block_Type_Registry::get_instance()->get_registered( $name );
			foreach ( $block['attrs'] ?? array() as $attribute => $value ) {
				if ( isset( $type->attributes[ $attribute ] ) ) {
					$valid = rest_validate_value_from_schema( $value, $type->attributes[ $attribute ], $name . '.' . $attribute );
					if ( is_wp_error( $valid ) ) {
						return $valid;
					}
				}
			}
			$result = self::validate_blocks( $block['innerBlocks'] ?? array(), $name );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}
		return true;
	}

	private static function fields(): string {
		// Never request rendered content: a read must not execute embedded blocks.
		return 'id,title.raw,status,content.raw,modified,modified_gmt';
	}

	private static function format_navigation( array $item, bool $full ): array {
		$data = array(
			'id' => (int) $item['id'], 'title' => $item['title']['raw'] ?? '',
			'status' => $item['status'] ?? '', 'modified' => $item['modified'] ?? null,
			'modified_gmt' => $item['modified_gmt'] ?? null,
		);
		$content = $item['content']['raw'] ?? '';
		$data['version'] = hash( 'sha256', wp_json_encode( array( $data, $content ) ) );
		if ( $full ) {
			$data['content'] = $content;
			$data['navigation_block'] = '<!-- wp:navigation {"ref":' . $data['id'] . '} /-->';
		}
		return $data;
	}

	private static function request( string $method, string $route, array $params ) {
		$request = new \WP_REST_Request( $method, $route );
		if ( 'GET' === $method ) {
			$request->set_query_params( $params );
		} else {
			$request->set_body_params( $params );
		}
		$response = rest_do_request( $request );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		return $response->is_error() ? $response->as_error() : $response;
	}

	private static function error( string $code, string $message, int $status ): \WP_Error {
		return new \WP_Error( 'kodanote_mcp_' . $code, $message, array( 'status' => $status ) );
	}

	private static function definition( string $name, string $title, string $description, array $properties, array $required, bool $read_only ): array {
		$schema = array( 'type' => 'object', 'additionalProperties' => false, 'properties' => $properties );
		if ( $required ) {
			$schema['required'] = $required;
		}
		return array(
			'name' => $name, 'title' => $title, 'description' => $description, 'inputSchema' => $schema,
			'annotations' => array( 'readOnlyHint' => $read_only, 'destructiveHint' => ! $read_only, 'idempotentHint' => $read_only, 'openWorldHint' => false ),
		);
	}
}
