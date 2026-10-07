<?php
/** Reusable pattern (wp_block) tools: edit one component, every page using it follows. */

namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Pattern_Tools {

	public static function definitions(): array {
		$id = array( 'type' => 'integer', 'minimum' => 1 );
		$categories = array( 'type' => 'array', 'maxItems' => 20, 'uniqueItems' => true, 'items' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 100 ), 'description' => 'Pattern category names. Replaces existing categories; an empty array removes them. Missing categories are created when you may manage categories.' );
		$status = array( 'type' => 'string', 'enum' => array( 'publish', 'draft' ), 'description' => 'Only published patterns render where they are inserted.' );
		$title = array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 1000 );
		$content = array( 'type' => 'string', 'maxLength' => 500000, 'description' => 'Complete WordPress block markup for the pattern, built from core blocks. Start from get_block_pattern or existing content rather than raw HTML.' );
		return array(
			self::definition( 'list_patterns', 'List reusable patterns', 'List reusable block patterns (synced and unsynced) the connected user may read, sorted by title: every published pattern, plus drafts you may edit. editable says whether you may change each one. A synced pattern is one shared component: pages embed it by reference, so editing it changes every page that uses it. Results exclude inaccessible items and may contain fewer than per_page items.', array(
				'search' => array( 'type' => 'string', 'maxLength' => 200 ),
				'sync_status' => array( 'type' => 'string', 'enum' => array( 'all', 'synced', 'unsynced' ), 'default' => 'all' ),
				'category' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 100, 'description' => 'Pattern category name or slug.' ),
				'status' => array( 'type' => 'string', 'enum' => array( 'any', 'publish', 'draft' ), 'default' => 'any' ),
				'include_usage' => array( 'type' => 'boolean', 'default' => false, 'description' => 'Add usage_count to each pattern.' ),
				'page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1 ),
				'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 50, 'default' => 20 ),
			), array(), true ),
			self::definition( 'get_pattern', 'Get a reusable pattern', 'Read a pattern\'s block markup, categories, version and where it is used. Anyone who may edit posts can read published patterns; editable says whether you may change it. usage lists the posts, pages, templates and other patterns that embed it; items you cannot open are only counted in hidden. For a synced pattern, insert_markup is the block to put in page content to embed it.', array( 'id' => $id ), array( 'id' ), true ),
			self::definition( 'create_pattern', 'Create a reusable pattern', 'Create a reusable block pattern. Synced by default: insert it into pages with its insert_markup and later edits apply everywhere. An unsynced pattern is only a starting point that is copied on insert. Published by default, because draft patterns render nothing where inserted; a published pattern has no public URL of its own. Requires publish permission.', array(
				'title' => $title,
				'content' => array_merge( $content, array( 'minLength' => 1 ) ),
				'sync_status' => array( 'type' => 'string', 'enum' => array( 'synced', 'unsynced' ), 'default' => 'synced', 'description' => 'Cannot be changed later.' ),
				'categories' => $categories,
				'status' => array_merge( $status, array( 'default' => 'publish' ) ),
			), array( 'title', 'content' ), false ),
			self::definition( 'update_pattern', 'Update a reusable pattern', 'Change only supplied fields of a pattern. Editing a published synced pattern immediately changes every page that embeds it; read get_pattern first and check its usage. Requires the version from get_pattern and permission to edit the pattern. The result reports current usage.', array(
				'id' => $id,
				'version' => array( 'type' => 'string', 'pattern' => '^[a-f0-9]{64}$', 'description' => 'The version returned by get_pattern. A stale version fails without writing.' ),
				'title' => $title,
				'content' => $content,
				'categories' => $categories,
				'status' => $status,
			), array( 'id', 'version' ), false ),
			self::definition( 'list_block_patterns', 'List ready-made section designs', 'List block patterns registered by the theme, plugins and WordPress, such as heroes, calls to action, features, pricing, testimonials and footers, sorted by title. Start a section from one of these with get_block_pattern instead of writing layout markup from scratch. They are designs to copy; for shared sections that stay in sync across pages, use list_patterns.', array(
				'search' => array( 'type' => 'string', 'maxLength' => 200, 'description' => 'Case-insensitive match on name, title, description and keywords.' ),
				'category' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 100, 'description' => 'A category slug from available_categories.' ),
				'page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1 ),
				'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100, 'default' => 50 ),
			), array(), true ),
			self::definition( 'get_block_pattern', 'Get a ready-made section design', 'Read the block markup of a registered pattern. Copy content into page content and adapt the text and images; the copy is independent of the pattern. block_types and post_types say where the design is meant to be used, for example core/template-part/footer.', array(
				'name' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 200, 'description' => 'Exact pattern name from list_block_patterns, such as twentytwentyfive/banner-hero.' ),
			), array( 'name' ), true ),
		);
	}

	public static function required_scope( string $name ): ?string {
		if ( in_array( $name, array( 'list_patterns', 'get_pattern', 'list_block_patterns', 'get_block_pattern' ), true ) ) {
			return 'content:read';
		}
		return in_array( $name, array( 'create_pattern', 'update_pattern' ), true ) ? 'content:write' : null;
	}

	/** Core maps pattern capabilities to post capabilities: creating one requires publish_posts. */
	public static function can_use( string $name ): bool {
		$type = get_post_type_object( 'wp_block' );
		if ( ! self::required_scope( $name ) || ! $type || ! get_current_user_id() || ! current_user_can( 'read' ) ) {
			return false;
		}
		if ( in_array( $name, array( 'list_block_patterns', 'get_block_pattern' ), true ) ) {
			return current_user_can( 'edit_posts' ) || current_user_can( 'edit_pages' );
		}
		return current_user_can( 'create_pattern' === $name ? $type->cap->create_posts : $type->cap->edit_posts );
	}

	/** @return array|\WP_Error */
	public static function call( string $name, array $input ) {
		foreach ( self::definitions() as $definition ) {
			if ( $name === $definition['name'] ) {
				$valid = rest_validate_value_from_schema( $input, $definition['inputSchema'], 'arguments' );
				if ( is_wp_error( $valid ) ) {
					return $valid;
				}
				if ( ! self::can_use( $name ) ) {
					return self::error( 'forbidden', 'Your current WordPress capabilities do not allow this pattern tool.', 403 );
				}
				switch ( $name ) {
					case 'list_patterns':
						return self::list_patterns( $input );
					case 'get_pattern':
						$post = self::pattern( $input['id'], false );
						return is_wp_error( $post ) ? $post : self::format( $post, true );
					case 'create_pattern':
						return self::create_pattern( $input );
					case 'update_pattern':
						return self::update_pattern( $input );
					case 'list_block_patterns':
						return self::list_block_patterns( $input );
					case 'get_block_pattern':
						$pattern = \WP_Block_Patterns_Registry::get_instance()->get_registered( $input['name'] );
						return $pattern ? self::format_block_pattern( $pattern, true ) : self::error( 'not_found', 'No registered block pattern has this name. Use list_block_patterns to find one.', 404 );
				}
			}
		}
		return self::error( 'unknown_tool', 'Unknown pattern tool.', 400 );
	}

	private static function list_patterns( array $input ): array {
		$type = get_post_type_object( 'wp_block' );
		$page = $input['page'] ?? 1;
		$per_page = $input['per_page'] ?? 20;
		$status = $input['status'] ?? 'any';
		$args = array(
			'post_type' => 'wp_block',
			'post_status' => 'any' === $status ? array( 'publish', 'draft', 'pending', 'future' ) : array( $status ),
			'posts_per_page' => $per_page, 'paged' => $page,
			'orderby' => 'title', 'order' => 'ASC', 'ignore_sticky_posts' => true,
		);
		if ( 'any' === $status && current_user_can( $type->cap->read_private_posts ) ) {
			$args['post_status'][] = 'private';
		}
		if ( isset( $input['search'] ) && '' !== $input['search'] ) {
			$args['s'] = $input['search'];
		}
		$sync = $input['sync_status'] ?? 'all';
		if ( 'unsynced' === $sync ) {
			$args['meta_query'] = array( array( 'key' => 'wp_pattern_sync_status', 'value' => 'unsynced' ) );
		} elseif ( 'synced' === $sync ) {
			$args['meta_query'] = array(
				'relation' => 'OR',
				array( 'key' => 'wp_pattern_sync_status', 'compare' => 'NOT EXISTS' ),
				array( 'key' => 'wp_pattern_sync_status', 'value' => 'unsynced', 'compare' => '!=' ),
			);
		}
		if ( isset( $input['category'] ) ) {
			$term = self::category_term( $input['category'] );
			if ( ! $term ) {
				return array( 'items' => array(), 'page' => $page, 'has_more' => false );
			}
			$args['tax_query'] = array( array( 'taxonomy' => 'wp_pattern_category', 'field' => 'term_id', 'terms' => $term->term_id ) );
		}
		$query = new \WP_Query( $args );
		$items = array();
		foreach ( $query->posts as $post ) {
			if ( current_user_can( 'read_post', $post->ID ) ) {
				$item = self::format( $post, false );
				if ( ! empty( $input['include_usage'] ) ) {
					$item['usage_count'] = Pattern_Usage::find( $post->ID, 0 )['total'];
				}
				$items[] = $item;
			}
		}
		return array( 'items' => $items, 'page' => $page, 'has_more' => $page < (int) $query->max_num_pages );
	}

	/** Registered designs only: hidden (inserter: false) patterns are internal to themes and templates. */
	private static function list_block_patterns( array $input ): array {
		$search = strtolower( trim( $input['search'] ?? '' ) );
		$category = $input['category'] ?? '';
		$items = array();
		foreach ( \WP_Block_Patterns_Registry::get_instance()->get_all_registered() as $pattern ) {
			if ( ( isset( $pattern['inserter'] ) && false === $pattern['inserter'] ) || ( '' !== $category && ! in_array( $category, (array) ( $pattern['categories'] ?? array() ), true ) ) ) {
				continue;
			}
			if ( '' !== $search ) {
				$haystack = implode( ' ', array( $pattern['name'], $pattern['title'] ?? '', $pattern['description'] ?? '', implode( ' ', (array) ( $pattern['keywords'] ?? array() ) ) ) );
				if ( false === strpos( strtolower( $haystack ), $search ) ) {
					continue;
				}
			}
			$items[] = self::format_block_pattern( $pattern, false );
		}
		usort( $items, static function ( $a, $b ) { return strcasecmp( $a['title'], $b['title'] ) ?: strcmp( $a['name'], $b['name'] ); } );
		$categories = array();
		foreach ( \WP_Block_Pattern_Categories_Registry::get_instance()->get_all_registered() as $registered ) {
			$categories[ $registered['name'] ] = (string) ( $registered['label'] ?? $registered['name'] );
		}
		ksort( $categories );
		$page = $input['page'] ?? 1;
		$per_page = $input['per_page'] ?? 50;
		return array(
			'items' => array_slice( $items, ( $page - 1 ) * $per_page, $per_page ),
			'page' => $page, 'total' => count( $items ), 'has_more' => $page * $per_page < count( $items ),
			'available_categories' => (object) $categories,
		);
	}

	private static function format_block_pattern( array $pattern, bool $full ): array {
		$data = array(
			'name' => (string) $pattern['name'],
			'title' => (string) ( $pattern['title'] ?? '' ),
			'description' => (string) ( $pattern['description'] ?? '' ),
			'categories' => array_values( (array) ( $pattern['categories'] ?? array() ) ),
			'block_types' => array_values( (array) ( $pattern['blockTypes'] ?? array() ) ),
			'post_types' => array_values( (array) ( $pattern['postTypes'] ?? array() ) ),
		);
		if ( $full ) {
			$data['content'] = (string) ( $pattern['content'] ?? '' );
		}
		return $data;
	}

	/** @return array|\WP_Error */
	private static function create_pattern( array $input ) {
		if ( '' === trim( wp_strip_all_tags( $input['title'] ) ) ) {
			return self::error( 'invalid_title', 'The pattern title must contain readable text.', 400 );
		}
		$terms = self::resolve_categories( $input['categories'] ?? array() );
		if ( is_wp_error( $terms ) ) {
			return $terms;
		}
		$params = array( 'context' => 'edit', 'title' => $input['title'], 'content' => $input['content'], 'status' => $input['status'] ?? 'publish' );
		if ( 'unsynced' === ( $input['sync_status'] ?? 'synced' ) ) {
			$params['meta'] = array( 'wp_pattern_sync_status' => 'unsynced' );
		}
		if ( isset( $input['categories'] ) ) {
			$ids = self::create_missing_categories( $terms );
			if ( is_wp_error( $ids ) ) {
				return $ids;
			}
			$params['wp_pattern_category'] = $ids;
		}
		$response = self::request( 'POST', '/wp/v2/blocks', $params );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$post = get_post( (int) $response->get_data()['id'] );
		return $post ? self::format( $post, true ) : self::error( 'pattern_unavailable', 'The pattern was created but cannot be read back.', 500 );
	}

	/** @return array|\WP_Error */
	private static function update_pattern( array $input ) {
		$post = self::pattern( $input['id'], true );
		if ( is_wp_error( $post ) ) {
			return $post;
		}
		if ( ! hash_equals( self::format( $post, false )['version'], $input['version'] ) ) {
			return self::error( 'version_conflict', 'The pattern changed after it was read. Read it again and reapply your changes to the new version.', 409 );
		}
		$params = array_intersect_key( $input, array_flip( array( 'title', 'content', 'status' ) ) );
		if ( ! $params && ! isset( $input['categories'] ) ) {
			return self::error( 'empty_update', 'Supply title, content, categories or status to update.', 400 );
		}
		if ( isset( $params['title'] ) && '' === trim( wp_strip_all_tags( $params['title'] ) ) ) {
			return self::error( 'invalid_title', 'The pattern title must contain readable text.', 400 );
		}
		if ( isset( $params['content'] ) && in_array( $post->ID, Pattern_Usage::refs_in( $params['content'] ), true ) ) {
			return self::error( 'self_reference', 'A pattern cannot embed itself.', 400 );
		}
		if ( isset( $input['categories'] ) ) {
			$terms = self::resolve_categories( $input['categories'] );
			if ( is_wp_error( $terms ) ) {
				return $terms;
			}
			$ids = self::create_missing_categories( $terms );
			if ( is_wp_error( $ids ) ) {
				return $ids;
			}
			$params['wp_pattern_category'] = $ids;
		}
		$params['context'] = 'edit';
		$response = self::request( 'POST', '/wp/v2/blocks/' . $post->ID, $params );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		clean_post_cache( $post->ID );
		return self::format( get_post( $post->ID ), true );
	}

	/**
	 * Core lets anyone who may edit posts read published patterns, so authors can embed shared
	 * components. Drafts by others, and every change, still need edit_post.
	 *
	 * @return \WP_Post|\WP_Error
	 */
	private static function pattern( int $id, bool $edit ) {
		$post = get_post( $id );
		if ( ! $post || 'wp_block' !== $post->post_type || 'trash' === $post->post_status ) {
			return self::error( 'not_found', 'No accessible pattern with this ID.', 404 );
		}
		if ( ! current_user_can( 'read_post', $id ) || ( $edit && ! current_user_can( 'edit_post', $id ) ) ) {
			return self::error( 'forbidden', $edit ? 'You may not edit this pattern.' : 'You may not read this pattern.', 403 );
		}
		return $post;
	}

	private static function format( \WP_Post $post, bool $full ): array {
		$synced = Pattern_Usage::is_synced( $post->ID );
		$data = array(
			'id' => $post->ID,
			'title' => $post->post_title,
			'slug' => $post->post_name,
			'status' => $post->post_status,
			'sync_status' => $synced ? 'synced' : 'unsynced',
			'categories' => self::category_names( $post->ID ),
			'author' => (int) $post->post_author,
			'modified' => mysql_to_rfc3339( $post->post_modified ),
			'editable' => current_user_can( 'edit_post', $post->ID ),
		);
		$data['version'] = hash( 'sha256', wp_json_encode( array( $post->ID, $post->post_modified_gmt, $post->post_title, $post->post_content, $post->post_status, $data['sync_status'], $data['categories'] ) ) );
		if ( $full ) {
			$data['content'] = $post->post_content;
			$data['insert_markup'] = $synced ? '<!-- wp:block {"ref":' . $post->ID . '} /-->' : '';
			$data['usage'] = Pattern_Usage::find( $post->ID );
		}
		return $data;
	}

	private static function category_names( int $id ): array {
		$names = wp_get_object_terms( $id, 'wp_pattern_category', array( 'fields' => 'names', 'orderby' => 'name', 'order' => 'ASC' ) );
		return is_array( $names ) ? array_values( array_map( 'strval', $names ) ) : array();
	}

	private static function category_term( string $name ) {
		$term = get_term_by( 'name', $name, 'wp_pattern_category' );
		return $term ?: get_term_by( 'slug', sanitize_title( $name ), 'wp_pattern_category' );
	}

	/**
	 * Check every requested category before any write.
	 *
	 * @return array|\WP_Error Existing term IDs and names still to create.
	 */
	private static function resolve_categories( array $names ) {
		$tax = get_taxonomy( 'wp_pattern_category' );
		if ( ! $tax || ( $names && ! current_user_can( $tax->cap->assign_terms ) ) ) {
			return self::error( 'forbidden', 'You may not assign pattern categories.', 403 );
		}
		$resolved = array( 'ids' => array(), 'missing' => array() );
		foreach ( $names as $name ) {
			$name = trim( sanitize_text_field( $name ) );
			if ( '' === $name ) {
				return self::error( 'invalid_category', 'Pattern category names must contain readable text.', 400 );
			}
			$term = self::category_term( $name );
			if ( $term ) {
				$resolved['ids'][] = (int) $term->term_id;
			} else {
				$resolved['missing'][] = $name;
			}
		}
		if ( $resolved['missing'] && ! current_user_can( $tax->cap->edit_terms ) ) {
			return self::error( 'forbidden', 'You may not create pattern categories. Use existing ones: ' . implode( ', ', $resolved['missing'] ) . ' do not exist.', 403 );
		}
		return $resolved;
	}

	/** @return int[]|\WP_Error */
	private static function create_missing_categories( array $resolved ) {
		$ids = $resolved['ids'];
		foreach ( $resolved['missing'] as $name ) {
			$term = wp_insert_term( $name, 'wp_pattern_category' );
			if ( is_wp_error( $term ) ) {
				$existing = $term->get_error_data( 'term_exists' );
				if ( ! $existing ) {
					return $term;
				}
				$ids[] = (int) $existing;
				continue;
			}
			$ids[] = (int) $term['term_id'];
		}
		return array_values( array_unique( $ids ) );
	}

	/** Internal REST dispatch keeps core sanitization and permission checks for writes. */
	private static function request( string $method, string $route, array $params ) {
		$request = new \WP_REST_Request( $method, $route );
		$request->set_body_params( $params );
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
