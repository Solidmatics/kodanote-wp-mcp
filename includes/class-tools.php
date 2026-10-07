<?php
/** Role-aware tool registry and content facade over WordPress REST controllers. */

namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Tools {

	/** MCP tool definitions. The transport validates input against these schemas. */
	public static function definitions(): array {
		$id = array( 'type' => 'integer', 'minimum' => 1 );
		$type = array( 'type' => 'string', 'enum' => array( 'post', 'page' ), 'default' => 'post' );
		$taxonomy = array( 'type' => 'string', 'enum' => array( 'category', 'post_tag' ), 'default' => 'category' );
		$fields = array(
			'title' => array( 'type' => 'string', 'maxLength' => 1000 ),
			'content' => array( 'type' => 'string', 'maxLength' => 500000, 'description' => 'HTML or WordPress block markup. Supply the complete replacement content when updating.' ),
			'excerpt' => array( 'type' => 'string', 'maxLength' => 10000 ),
			'slug' => array( 'type' => 'string', 'maxLength' => 200 ),
			'status' => array( 'type' => 'string', 'enum' => array( 'draft', 'pending', 'publish', 'future', 'private' ) ),
			'date' => array( 'type' => 'string', 'format' => 'date-time', 'description' => 'Publication date in RFC 3339 format. Scheduling requires a future date.' ),
			'categories' => array( 'type' => 'array', 'items' => $id, 'maxItems' => 100, 'uniqueItems' => true, 'description' => 'Existing category IDs, for posts only. Replaces existing categories.' ),
			'tags' => array( 'type' => 'array', 'items' => $id, 'maxItems' => 100, 'uniqueItems' => true, 'description' => 'Existing tag IDs, for posts only. Replaces existing tags.' ),
			'featured_media_id' => array( 'type' => 'integer', 'minimum' => 0, 'description' => 'An editable image attachment ID; 0 removes the featured image.' ),
			'seo' => self::schema( array(
				'title' => array( 'type' => 'string', 'maxLength' => 1000 ),
				'description' => array( 'type' => 'string', 'maxLength' => 5000 ),
				'focus_keyphrase' => array( 'type' => 'string', 'maxLength' => 500 ),
			) ),
		);
		return array_merge( array(
			self::definition( 'get_site_info', 'Get site information', 'Get site identity and the connected user\'s content permissions.', array(), array(), true ),
			self::definition( 'list_content', 'List posts or pages', 'List content the connected user can read and edit. Results exclude inaccessible items and may contain fewer than per_page items. Pagination refers to the underlying WordPress query.', array(
				'post_type' => $type,
				'status' => array( 'type' => 'string', 'enum' => array( 'any', 'draft', 'pending', 'publish', 'future', 'private', 'trash' ), 'default' => 'any' ),
				'search' => array( 'type' => 'string', 'maxLength' => 200 ),
				'page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1 ),
				'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 50, 'default' => 20 ),
				'orderby' => array( 'type' => 'string', 'enum' => array( 'date', 'modified', 'title' ), 'default' => 'date' ),
				'order' => array( 'type' => 'string', 'enum' => array( 'asc', 'desc' ), 'default' => 'desc' ),
			), array(), true ),
			self::definition( 'get_content', 'Get a post or page', 'Read a post or page, including raw content and known SEO fields. Requires permission to read and edit that item.', array( 'id' => $id ), array( 'id' ), true ),
			self::definition( 'create_content', 'Create a post or page', 'Create content as the connected user. Defaults to draft. Publishing, scheduling and private content require publish permission. SEO fields require Yoast SEO.', array_merge( array( 'post_type' => $type ), $fields ), array( 'title' ), false ),
			self::definition( 'update_content', 'Update a post or page', 'Change only supplied fields. Publishing or changing published, scheduled or private content requires publish permission. Content Publisher hooks remain active and may mark body edits as manually managed. SEO fields require Yoast SEO.', array_merge( array( 'id' => $id ), $fields ), array( 'id' ), false, true ),
			self::definition( 'trash_content', 'Trash a post or page', 'Move content to WordPress trash. Never permanently deletes. Fails if WordPress trash is disabled. Requires delete permission and publish permission for published, scheduled or private content.', array( 'id' => $id ), array( 'id' ), false, true, true ),
			self::definition( 'list_terms', 'List categories or tags', 'List existing categories or tags, including empty terms.', array(
				'taxonomy' => $taxonomy,
				'search' => array( 'type' => 'string', 'maxLength' => 200 ),
				'page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1 ),
				'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 50 ),
			), array(), true ),
			self::definition( 'create_term', 'Create a category or tag', 'Create a category or tag if the connected user may manage that taxonomy.', array(
				'taxonomy' => $taxonomy,
				'name' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 200 ),
				'slug' => array( 'type' => 'string', 'maxLength' => 200 ),
				'description' => array( 'type' => 'string', 'maxLength' => 5000 ),
				'parent' => array( 'type' => 'integer', 'minimum' => 0, 'description' => 'Parent category ID. Only valid for categories.' ),
			), array( 'name' ), false ),
		), Pattern_Tools::definitions(), Appearance_Tools::definitions(), Site_Tools::definitions(), Navigation_Tools::definitions(), Layout_Tools::definitions(), Audit::definitions() );
	}

	public static function required_scope( string $name ): ?string {
		foreach ( self::providers() as $provider ) {
			$scope = $provider::required_scope( $name );
			if ( null !== $scope ) { return $scope; }
		}
		if ( in_array( $name, array( 'get_site_info', 'list_content', 'get_content', 'list_terms' ), true ) ) {
			return 'content:read';
		}
		return in_array( $name, array( 'create_content', 'update_content', 'trash_content', 'create_term' ), true ) ? 'content:write' : null;
	}

	/** Capabilities govern discovery as well as execution; never assume a role name. */
	public static function can_use( string $name ): bool {
		if ( ! get_current_user_id() || ! current_user_can( 'read' ) ) { return false; }
		foreach ( self::providers() as $provider ) {
			if ( null !== $provider::required_scope( $name ) ) { return $provider::can_use( $name ); }
		}
		if ( 'get_site_info' === $name ) { return (bool) Access::available_scopes(); }
		if ( 'list_terms' === $name || 'create_term' === $name ) {
			$cap = 'create_term' === $name ? 'edit_terms' : 'assign_terms';
			foreach ( array( 'category', 'post_tag' ) as $taxonomy ) {
				$tax = get_taxonomy( $taxonomy );
				if ( $tax && current_user_can( $tax->cap->$cap ) ) { return true; }
			}
			return false;
		}
		if ( in_array( $name, array( 'list_content', 'get_content', 'create_content', 'update_content', 'trash_content' ), true ) ) {
			$cap = 'trash_content' === $name ? 'delete_posts' : ( 'create_content' === $name ? 'create_posts' : 'edit_posts' );
			foreach ( array( 'post', 'page' ) as $type ) {
				$pto = get_post_type_object( $type );
				if ( $pto && current_user_can( $pto->cap->$cap ) ) { return true; }
			}
		}
		return false;
	}

	/** @return array|\WP_Error */
	public static function call( string $name, array $arguments ) {
		$definition = null;
		foreach ( self::definitions() as $candidate ) {
			if ( $candidate['name'] === $name ) {
				$definition = $candidate;
				break;
			}
		}
		if ( ! $definition ) {
			return self::error( 'unknown_tool', 'Unknown content tool.', 400 );
		}
		if ( ! self::can_use( $name ) ) {
			return self::error( 'forbidden', 'Your current WordPress capabilities do not allow this tool.', 403 );
		}
		$valid = rest_validate_value_from_schema( $arguments, $definition['inputSchema'], 'arguments' );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		if ( ! get_current_user_id() || ! current_user_can( 'read' ) ) {
			return self::error( 'forbidden', 'A connected WordPress user with read permission is required.', 403 );
		}
		foreach ( self::providers() as $provider ) {
			if ( null !== $provider::required_scope( $name ) ) { return $provider::call( $name, $arguments ); }
		}
		switch ( $name ) {
			case 'get_site_info':
				return self::site_info();
			case 'list_content':
				return self::list_content( $arguments );
			case 'get_content':
				return self::get_content( $arguments['id'] );
			case 'create_content':
				return self::write_content( $arguments, false );
			case 'update_content':
				return self::write_content( $arguments, true );
			case 'trash_content':
				return self::trash_content( $arguments['id'] );
			case 'list_terms':
				return self::terms( $arguments, false );
			case 'create_term':
				return self::terms( $arguments, true );
		}
		return self::error( 'unknown_tool', 'Unknown content tool.', 400 );
	}

	private static function site_info(): array {
		$user = wp_get_current_user();
		return array(
			'name' => get_bloginfo( 'name' ),
			'description' => get_bloginfo( 'description' ),
			'url' => home_url( '/' ),
			'timezone' => wp_timezone_string(),
			'user' => array( 'id' => $user->ID, 'display_name' => $user->display_name, 'roles' => array_values( $user->roles ) ),
			'available_scopes' => Access::available_scopes(),
			'permissions' => array(
				'edit_posts' => current_user_can( 'edit_posts' ),
				'edit_pages' => current_user_can( 'edit_pages' ),
				'publish_posts' => current_user_can( 'publish_posts' ),
				'publish_pages' => current_user_can( 'publish_pages' ),
				'edit_theme_options' => current_user_can( 'edit_theme_options' ),
				'manage_options' => current_user_can( 'manage_options' ),
				'upload_files' => current_user_can( 'upload_files' ),
				'activate_plugins' => current_user_can( 'activate_plugins' ),
				'list_users' => current_user_can( 'list_users' ),
			),
			'yoast_seo_available' => self::has_yoast(),
		);
	}

	private static function providers(): array {
		return array( Pattern_Tools::class, Appearance_Tools::class, Site_Tools::class, Navigation_Tools::class, Layout_Tools::class, Audit::class );
	}

	/** @return array|\WP_Error */
	private static function list_content( array $input ) {
		$type = $input['post_type'] ?? 'post';
		$pto = get_post_type_object( $type );
		if ( ! $pto || ! current_user_can( $pto->cap->edit_posts ) ) {
			return self::error( 'forbidden', 'You may not list content of this type.', 403 );
		}
		$status = $input['status'] ?? 'any';
		$statuses = 'any' === $status ? array( 'draft', 'pending', 'publish', 'future', 'private' ) : array( $status );
		if ( ! current_user_can( $pto->cap->read_private_posts ) ) {
			$statuses = array_values( array_diff( $statuses, array( 'private' ) ) );
		}
		$page = $input['page'] ?? 1;
		if ( ! $statuses ) {
			return array( 'items' => array(), 'page' => $page, 'has_more' => false );
		}
		$params = array(
			'context' => 'edit', 'status' => $statuses,
			'page' => $page, 'per_page' => $input['per_page'] ?? 20,
			'orderby' => $input['orderby'] ?? 'date', 'order' => $input['order'] ?? 'desc',
			'search' => $input['search'] ?? '',
			'_fields' => 'id,type,status,title,slug,link,date,modified,excerpt,author',
		);
		if ( ! current_user_can( $pto->cap->edit_others_posts ) ) {
			$params['author'] = get_current_user_id();
		}
		$response = self::request( 'GET', self::content_route( $type ), $params );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$items = array();
		foreach ( $response->get_data() as $item ) {
			if ( current_user_can( 'read_post', $item['id'] ) && current_user_can( 'edit_post', $item['id'] ) ) {
				$items[] = self::format_content( $item, false );
			}
		}
		$headers = $response->get_headers();
		return array( 'items' => $items, 'page' => $page, 'has_more' => $page < (int) ( $headers['X-WP-TotalPages'] ?? 0 ) );
	}

	/** @return array|\WP_Error */
	private static function get_content( int $id ) {
		$post = self::editable_post( $id );
		if ( is_wp_error( $post ) ) {
			return $post;
		}
		$response = self::request( 'GET', self::content_route( $post->post_type ) . '/' . $id, array( 'context' => 'edit' ) );
		return is_wp_error( $response ) ? $response : self::format_content( $response->get_data(), true );
	}

	/** @return array|\WP_Error */
	private static function write_content( array $input, bool $update ) {
		$post = $update ? self::editable_post( $input['id'] ) : null;
		if ( is_wp_error( $post ) ) {
			return $post;
		}
		$type = $post ? $post->post_type : ( $input['post_type'] ?? 'post' );
		$pto = get_post_type_object( $type );
		if ( ! $pto || ! current_user_can( $update ? $pto->cap->edit_posts : $pto->cap->create_posts ) ) {
			return self::error( 'forbidden', 'You may not create or edit this content type.', 403 );
		}
		if ( ! $update && '' === trim( $input['title'] ) ) {
			return self::error( 'invalid_title', 'A nonempty title is required.', 400 );
		}
		$protected = array( 'publish', 'future', 'private' );
		$status = $input['status'] ?? ( $post ? $post->post_status : 'draft' );
		if ( ( in_array( $status, $protected, true ) || ( $post && in_array( $post->post_status, $protected, true ) ) ) && ! current_user_can( $pto->cap->publish_posts ) ) {
			return self::error( 'forbidden', 'Publish permission is required to publish or change published, scheduled or private content.', 403 );
		}
		if ( 'future' === $status ) {
			$date = $input['date'] ?? ( $post ? $post->post_date : '' );
			try {
				$scheduled = new \DateTimeImmutable( $date, wp_timezone() );
			} catch ( \Exception $error ) {
				return self::error( 'invalid_date', 'Scheduling requires a valid future date.', 400 );
			}
			if ( '' === $date || $scheduled->getTimestamp() <= time() ) {
				return self::error( 'invalid_date', 'Scheduling requires a valid future date.', 400 );
			}
		}
		$valid = self::validate_relations( $input, $type );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		$params = array( 'context' => 'edit' );
		foreach ( array( 'title', 'content', 'excerpt', 'slug', 'status', 'date', 'categories', 'tags' ) as $field ) {
			if ( array_key_exists( $field, $input ) ) {
				$params[ $field ] = $input[ $field ];
			}
		}
		if ( ! $update && ! isset( $params['status'] ) ) {
			$params['status'] = 'draft';
		}
		if ( isset( $input['featured_media_id'] ) ) {
			$params['featured_media'] = $input['featured_media_id'];
		}
		$route = self::content_route( $type ) . ( $post ? '/' . $post->ID : '' );
		$response = self::request( 'POST', $route, $params );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$data = $response->get_data();
		if ( isset( $input['seo'] ) ) {
			foreach ( self::seo_keys() as $key => $meta_key ) {
				if ( array_key_exists( $key, $input['seo'] ) ) {
					update_post_meta( $data['id'], $meta_key, sanitize_text_field( $input['seo'][ $key ] ) );
				}
			}
		}
		return self::format_content( $data, true );
	}

	/** Validate related changes before a REST write can create partial results. */
	private static function validate_relations( array $input, string $type ) {
		foreach ( array( 'categories' => 'category', 'tags' => 'post_tag' ) as $field => $name ) {
			if ( ! isset( $input[ $field ] ) ) {
				continue;
			}
			$tax = get_taxonomy( $name );
			if ( 'post' !== $type || ! $tax || ! current_user_can( $tax->cap->assign_terms ) ) {
				return self::error( 'forbidden', 'You may not assign these terms to this content type.', 403 );
			}
			foreach ( $input[ $field ] as $id ) {
				$term = get_term( $id, $name );
				if ( ! $term || is_wp_error( $term ) ) {
					return self::error( 'invalid_term', 'A supplied category or tag does not exist in that taxonomy.', 400 );
				}
			}
		}
		if ( ! empty( $input['featured_media_id'] ) && ( ! wp_attachment_is_image( $input['featured_media_id'] ) || ! current_user_can( 'edit_post', $input['featured_media_id'] ) ) ) {
			return self::error( 'invalid_media', 'The featured image must be an existing image attachment you may edit.', 403 );
		}
		if ( isset( $input['seo'] ) && ! self::has_yoast() ) {
			return self::error( 'seo_unavailable', 'Yoast SEO must be active to write SEO fields.', 400 );
		}
		return true;
	}

	/** @return array|\WP_Error */
	private static function trash_content( int $id ) {
		$post = self::editable_post( $id );
		if ( is_wp_error( $post ) ) {
			return $post;
		}
		$pto = get_post_type_object( $post->post_type );
		if ( ! current_user_can( 'delete_post', $id ) || ( in_array( $post->post_status, array( 'publish', 'future', 'private' ), true ) && ! current_user_can( $pto->cap->publish_posts ) ) ) {
			return self::error( 'forbidden', 'You may not trash this content.', 403 );
		}
		if ( 'trash' === $post->post_status ) {
			return array( 'id' => $id, 'status' => 'trash' );
		}
		if ( defined( 'EMPTY_TRASH_DAYS' ) && ! EMPTY_TRASH_DAYS ) {
			return self::error( 'trash_disabled', 'WordPress trash is disabled. Permanent deletion is not available through MCP.', 400 );
		}
		$response = self::request( 'DELETE', self::content_route( $post->post_type ) . '/' . $id, array( 'force' => false ) );
		return is_wp_error( $response ) ? $response : array( 'id' => $id, 'status' => 'trash' );
	}

	/** @return array|\WP_Error */
	private static function terms( array $input, bool $create ) {
		$name = $input['taxonomy'] ?? 'category';
		$tax = get_taxonomy( $name );
		if ( ! $tax || ! current_user_can( $create ? $tax->cap->edit_terms : $tax->cap->assign_terms ) ) {
			return self::error( 'forbidden', 'You may not access this taxonomy.', 403 );
		}
		if ( $create && ( '' === trim( $input['name'] ) || ( 'post_tag' === $name && isset( $input['parent'] ) ) ) ) {
			return self::error( 'invalid_term', 'Use a nonempty name. Parent is only supported for categories.', 400 );
		}
		$params = $input;
		unset( $params['taxonomy'] );
		if ( ! $create ) {
			$params['hide_empty'] = false;
			$params['per_page'] = $input['per_page'] ?? 50;
			$params['page'] = $input['page'] ?? 1;
		}
		$response = self::request( $create ? 'POST' : 'GET', '/wp/v2/' . ( 'category' === $name ? 'categories' : 'tags' ), $params );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		if ( $create ) {
			return self::format_term( $response->get_data() );
		}
		$headers = $response->get_headers();
		return array(
			'taxonomy' => $name, 'items' => array_map( array( self::class, 'format_term' ), $response->get_data() ),
			'page' => $params['page'], 'has_more' => $params['page'] < (int) ( $headers['X-WP-TotalPages'] ?? 0 ),
		);
	}

	/** @return \WP_Post|\WP_Error */
	private static function editable_post( int $id ) {
		$post = get_post( $id );
		if ( ! $post || ! in_array( $post->post_type, array( 'post', 'page' ), true ) ) {
			return self::error( 'not_found', 'No accessible post or page with this ID.', 404 );
		}
		if ( ! current_user_can( 'read_post', $id ) || ! current_user_can( 'edit_post', $id ) ) {
			return self::error( 'forbidden', 'You may not read and edit this item.', 403 );
		}
		return $post;
	}

	/** Internal REST dispatch retains core validation, sanitization and permission checks. */
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

	private static function content_route( string $type ): string {
		return '/wp/v2/' . ( 'page' === $type ? 'pages' : 'posts' );
	}

	private static function format_content( array $item, bool $full ): array {
		$data = array();
		foreach ( array( 'id', 'type', 'status', 'slug', 'link', 'date', 'modified', 'author' ) as $key ) {
			if ( array_key_exists( $key, $item ) ) {
				$data[ $key ] = $item[ $key ];
			}
		}
		$data['title'] = $item['title']['raw'] ?? '';
		$data['excerpt'] = $item['excerpt']['raw'] ?? '';
		if ( $full ) {
			$data['content'] = $item['content']['raw'] ?? '';
			$data['categories'] = $item['categories'] ?? array();
			$data['tags'] = $item['tags'] ?? array();
			$data['featured_media_id'] = $item['featured_media'] ?? 0;
			$data['seo'] = array();
			foreach ( self::seo_keys() as $key => $meta_key ) {
				$data['seo'][ $key ] = (string) get_post_meta( $item['id'], $meta_key, true );
			}
		}
		return $data;
	}

	private static function format_term( array $item ): array {
		return array_intersect_key( $item, array_flip( array( 'id', 'name', 'slug', 'taxonomy', 'description', 'parent', 'count', 'link' ) ) );
	}

	private static function seo_keys(): array {
		return array( 'title' => '_yoast_wpseo_title', 'description' => '_yoast_wpseo_metadesc', 'focus_keyphrase' => '_yoast_wpseo_focuskw' );
	}

	private static function has_yoast(): bool {
		return defined( 'WPSEO_VERSION' ) || class_exists( 'WPSEO_Options' );
	}

	private static function error( string $code, string $message, int $status ): \WP_Error {
		return new \WP_Error( 'kodanote_mcp_' . $code, $message, array( 'status' => $status ) );
	}

	private static function schema( array $properties, array $required = array() ): array {
		$schema = array( 'type' => 'object', 'additionalProperties' => false );
		if ( $properties ) {
			$schema['properties'] = $properties;
		}
		if ( $required ) {
			$schema['required'] = $required;
		}
		return $schema;
	}

	private static function definition( string $name, string $title, string $description, array $properties, array $required, bool $read_only, bool $idempotent = false, bool $destructive = false ): array {
		return array(
			'name' => $name, 'title' => $title, 'description' => $description,
			'inputSchema' => self::schema( $properties, $required ),
			'annotations' => array( 'readOnlyHint' => $read_only, 'destructiveHint' => $destructive, 'idempotentHint' => $read_only || $idempotent, 'openWorldHint' => false ),
		);
	}
}
