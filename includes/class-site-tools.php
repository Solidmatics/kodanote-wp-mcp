<?php
/** Capability-gated administration and media tools with explicit field allowlists. */

namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Site_Tools {

	public static function definitions(): array {
		$id = array( 'type' => 'integer', 'minimum' => 1 );
		$version = array( 'type' => 'string', 'pattern' => '^[a-f0-9]{64}$', 'description' => 'Version returned by the corresponding read tool. Read again and review changes after a conflict.' );
		$pagination = array(
			'page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1 ),
			'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 50, 'default' => 20 ),
		);
		$search = array( 'search' => array( 'type' => 'string', 'maxLength' => 200 ) );
		$settings = self::schema( self::settings_properties() );
		$settings['minProperties'] = 1;
		return array(
			self::definition( 'get_site_settings', 'Get site settings', 'Read supported general, writing, homepage, reading, discussion, media-size and permalink settings with a version for updates. Requires manage_options. Credentials, site URLs, email, registration and security settings are excluded.', array(), array(), true ),
			self::definition( 'update_site_settings', 'Update site settings', 'Update only supplied supported settings after validating the complete request. Requires manage_options and a current get_site_settings version. Homepage/blog pages must be distinct, published, password-free pages you can read and edit. Permalink changes affect public URLs/SEO and require existing non-index pretty routing; only safe presets are accepted. Updates database rewrite rules without changing server files. Image sizes affect future uploads; existing images are not regenerated.', array( 'version' => $version, 'settings' => $settings ), array( 'version', 'settings' ), false ),
			self::definition( 'list_plugins', 'List installed plugins', 'Read plugin identifiers, names, versions and activation status. Requires activate_plugins. Does not expose files or options, or change plugins.', $pagination, array(), true ),
			self::definition( 'list_users', 'List site users', 'Read user IDs, display names, public slugs and roles. Requires list_users. Email addresses, login names and credentials are excluded.', array_merge( $pagination, $search ), array(), true ),
			self::definition( 'list_media', 'List media', 'List existing attachments the connected user may read and edit. Requires upload_files. Results may be shorter than per_page after permission filtering; pagination refers to the WordPress query.', array_merge( $pagination, $search, array(
				'orderby' => array( 'type' => 'string', 'enum' => array( 'date', 'modified', 'title' ), 'default' => 'date' ),
				'order' => array( 'type' => 'string', 'enum' => array( 'asc', 'desc' ), 'default' => 'desc' ),
			) ), array(), true ),
			self::definition( 'get_media', 'Get media metadata', 'Read attachment metadata and its update version. Requires upload_files and permission to read and edit the attachment. Does not expose filesystem paths.', array( 'id' => $id ), array( 'id' ), true ),
			self::definition( 'update_media', 'Update media metadata', 'Update supplied attachment text fields or its parent post/page. Requires upload_files, attachment read/edit permissions and a current version from get_media. Does not upload, fetch, replace or delete files.', array(
				'id' => $id,
				'version' => $version,
				'title' => array( 'type' => 'string', 'maxLength' => 1000 ),
				'caption' => array( 'type' => 'string', 'maxLength' => 10000 ),
				'description' => array( 'type' => 'string', 'maxLength' => 50000 ),
				'alt_text' => array( 'type' => 'string', 'maxLength' => 5000 ),
				'parent' => array( 'type' => 'integer', 'minimum' => 0, 'description' => 'An existing readable/editable post or page ID, or 0 to detach.' ),
			), array( 'id', 'version' ), false ),
		);
	}

	public static function required_scope( string $name ): ?string {
		$scopes = array(
			'get_site_settings' => 'settings:read', 'update_site_settings' => 'settings:write',
			'list_plugins' => 'plugins:read', 'list_users' => 'users:read',
			'list_media' => 'media:read', 'get_media' => 'media:read', 'update_media' => 'media:write',
		);
		return $scopes[ $name ] ?? null;
	}

	/** Capabilities are checked again on every call, so role changes take immediate effect. */
	public static function can_use( string $name ): bool {
		$capabilities = array(
			'get_site_settings' => 'manage_options', 'update_site_settings' => 'manage_options',
			'list_plugins' => 'activate_plugins', 'list_users' => 'list_users',
			'list_media' => 'upload_files', 'get_media' => 'upload_files', 'update_media' => 'upload_files',
		);
		return isset( $capabilities[ $name ] ) && get_current_user_id() && current_user_can( 'read' ) && current_user_can( $capabilities[ $name ] );
	}

	/** @return array|\WP_Error */
	public static function call( string $name, array $arguments ) {
		$definition = null;
		foreach ( self::definitions() as $candidate ) {
			if ( $name === $candidate['name'] ) {
				$definition = $candidate;
				break;
			}
		}
		if ( ! $definition ) {
			return self::error( 'unknown_tool', 'Unknown site administration tool.', 400 );
		}
		if ( ! self::can_use( $name ) ) {
			return self::error( 'forbidden', 'The connected WordPress user lacks the capability required for this tool.', 403 );
		}
		$valid = rest_validate_value_from_schema( $arguments, $definition['inputSchema'], 'arguments' );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		switch ( $name ) {
			case 'get_site_settings':
				return self::get_settings();
			case 'update_site_settings':
				return self::update_settings( $arguments );
			case 'list_plugins':
				return self::list_plugins( $arguments );
			case 'list_users':
				return self::list_users( $arguments );
			case 'list_media':
				return self::list_media( $arguments );
			case 'get_media':
				return self::get_media( $arguments['id'] );
			case 'update_media':
				return self::update_media( $arguments );
		}
		return self::error( 'unknown_tool', 'Unknown site administration tool.', 400 );
	}

	private static function settings_properties(): array {
		$properties = array(
			'title' => array( 'type' => 'string', 'maxLength' => 1000 ),
			'description' => array( 'type' => 'string', 'maxLength' => 5000 ),
			'timezone' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 100, 'description' => 'An IANA timezone name, such as Europe/Vilnius or UTC.' ),
			'date_format' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 100 ),
			'time_format' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 100 ),
			'start_of_week' => array( 'type' => 'integer', 'minimum' => 0, 'maximum' => 6 ),
			'posts_per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100 ),
			'default_category' => array( 'type' => 'integer', 'minimum' => 1 ),
			'default_post_format' => array( 'type' => 'string', 'enum' => array( '0', 'aside', 'chat', 'gallery', 'link', 'image', 'quote', 'status', 'video', 'audio' ), 'description' => 'Use 0 for the standard post format.' ),
			'show_on_front' => array( 'type' => 'string', 'enum' => array( 'posts', 'page' ), 'description' => 'Show latest posts or a static page on the homepage. A static page requires page_on_front.' ),
			'page_on_front' => array( 'type' => 'integer', 'minimum' => 0, 'description' => 'Published, password-free homepage page ID, or 0 to unset when show_on_front is posts.' ),
			'page_for_posts' => array( 'type' => 'integer', 'minimum' => 0, 'description' => 'Published, password-free blog page ID, distinct from the homepage; 0 leaves no separate blog page.' ),
			'posts_per_rss' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100 ),
			'rss_use_excerpt' => array( 'type' => 'boolean', 'description' => 'Use excerpts rather than full posts in feeds.' ),
			'use_smilies' => array( 'type' => 'boolean', 'description' => 'Convert text emoticons to graphics when displayed.' ),
			'default_comment_status' => array( 'type' => 'string', 'enum' => array( 'open', 'closed' ), 'description' => 'Default for comments on new posts; existing post settings are preserved.' ),
			'close_comments_for_old_posts' => array( 'type' => 'boolean' ),
			'close_comments_days_old' => array( 'type' => 'integer', 'minimum' => 0, 'maximum' => 36500 ),
			'thread_comments' => array( 'type' => 'boolean' ),
			'thread_comments_depth' => array( 'type' => 'integer', 'minimum' => 2, 'maximum' => 10 ),
			'page_comments' => array( 'type' => 'boolean' ),
			'comments_per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100 ),
			'default_comments_page' => array( 'type' => 'string', 'enum' => array( 'newest', 'oldest' ) ),
			'comment_order' => array( 'type' => 'string', 'enum' => array( 'asc', 'desc' ) ),
			'show_avatars' => array( 'type' => 'boolean' ),
			'avatar_rating' => array( 'type' => 'string', 'enum' => array( 'G', 'PG', 'R', 'X' ) ),
			'avatar_default' => array( 'type' => 'string', 'enum' => array( 'mystery', 'blank', 'gravatar_default', 'identicon', 'wavatar', 'monsterid', 'retro', 'robohash' ) ),
			'thumbnail_crop' => array( 'type' => 'boolean', 'description' => 'Crop new thumbnail images to their exact configured dimensions.' ),
			'permalink_structure' => array(
				'type' => 'string',
				'enum' => array( '/%postname%/', '/%year%/%monthnum%/%day%/%postname%/', '/%year%/%monthnum%/%postname%/', '/archives/%post_id%', '/archives/%post_id%/', '/%category%/%postname%/' ),
				'description' => 'Pretty permalink preset. Changes public post URLs and may affect SEO. Existing pretty-permalink server routing is required. Plain, index.php, and arbitrary custom structures are excluded to keep the OAuth resource URL stable.',
			),
		);
		foreach ( array( 'thumbnail_size_w', 'thumbnail_size_h', 'medium_size_w', 'medium_size_h', 'large_size_w', 'large_size_h' ) as $name ) {
			$properties[ $name ] = array( 'type' => 'integer', 'minimum' => 0, 'maximum' => 4096, 'description' => 'Maximum image dimension in pixels for future uploads. Zero removes this dimension constraint; existing files are not regenerated.' );
		}
		return $properties;
	}

	/** Additional bounded core options not exposed by WordPress's settings REST controller. */
	private static function additional_settings_defaults(): array {
		return array(
			'posts_per_rss' => 10, 'rss_use_excerpt' => false,
			'close_comments_for_old_posts' => false, 'close_comments_days_old' => 14,
			'thread_comments' => true, 'thread_comments_depth' => 5,
			'page_comments' => false, 'comments_per_page' => 50, 'default_comments_page' => 'newest', 'comment_order' => 'asc',
			'show_avatars' => true, 'avatar_rating' => 'G', 'avatar_default' => 'mystery',
			'thumbnail_size_w' => 150, 'thumbnail_size_h' => 150, 'thumbnail_crop' => true,
			'medium_size_w' => 300, 'medium_size_h' => 300, 'large_size_w' => 1024, 'large_size_h' => 1024,
			'permalink_structure' => '',
		);
	}

	private static function get_settings() {
		$response = self::request( 'GET', '/wp/v2/settings', array( '_fields' => implode( ',', array_keys( self::settings_properties() ) ) ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$data = $response->get_data();
		$properties = self::settings_properties();
		foreach ( self::additional_settings_defaults() as $name => $default ) {
			$value = get_option( $name, $default );
			if ( 'boolean' === $properties[ $name ]['type'] ) {
				$value = rest_sanitize_boolean( $value );
			} elseif ( 'integer' === $properties[ $name ]['type'] ) {
				$value = (int) $value;
			} else {
				$value = (string) $value;
			}
			$data[ $name ] = $value;
		}
		return self::format_settings( $data );
	}

	private static function format_settings( array $data ): array {
		$settings = array();
		foreach ( array_keys( self::settings_properties() ) as $key ) {
			if ( array_key_exists( $key, $data ) ) {
				$settings[ $key ] = $data[ $key ];
			}
		}
		return array( 'settings' => $settings, 'version' => self::fingerprint( $settings ) );
	}

	private static function update_settings( array $input ) {
		$settings = rest_sanitize_value_from_schema( $input['settings'], self::schema( self::settings_properties() ) );
		if ( is_wp_error( $settings ) ) {
			return $settings;
		}
		if ( ! $settings ) {
			return self::error( 'empty_update', 'Supply at least one supported site setting to update.', 400 );
		}
		// Validate relationships before dispatch, since the settings controller writes each option in turn.
		if ( isset( $settings['timezone'] ) && ! in_array( $settings['timezone'], timezone_identifiers_list( \DateTimeZone::ALL_WITH_BC ), true ) ) {
			return self::error( 'invalid_timezone', 'Use a valid IANA timezone name, such as Europe/Vilnius or UTC.', 400 );
		}
		if ( isset( $settings['default_category'] ) ) {
			$category = get_term( $settings['default_category'], 'category' );
			if ( ! $category || is_wp_error( $category ) ) {
				return self::error( 'invalid_category', 'The default category must already exist.', 400 );
			}
		}
		$current = self::get_settings();
		if ( is_wp_error( $current ) ) {
			return $current;
		}
		if ( ! hash_equals( $current['version'], $input['version'] ) ) {
			return self::error( 'conflict', 'Site settings changed since they were read. Read them again and review the current settings before retrying.', 409 );
		}
		if ( array_intersect_key( $settings, array_flip( array( 'show_on_front', 'page_on_front', 'page_for_posts' ) ) ) ) {
			$effective = array_merge( $current['settings'], $settings );
			$front = (int) ( $effective['page_on_front'] ?? 0 );
			$posts = (int) ( $effective['page_for_posts'] ?? 0 );
			if ( 'page' === ( $effective['show_on_front'] ?? 'posts' ) && ! $front ) {
				return self::error( 'invalid_homepage', 'A static homepage requires a published page_on_front. Use show_on_front=posts to clear it.', 400 );
			}
			if ( $front && $front === $posts ) {
				return self::error( 'invalid_homepage', 'Homepage and posts page must be different pages.', 400 );
			}
			foreach ( array_unique( array( $front, $posts ) ) as $page_id ) {
				if ( ! $page_id ) {
					continue;
				}
				$page = get_post( $page_id );
				if ( ! $page || 'page' !== $page->post_type || 'publish' !== $page->post_status || '' !== $page->post_password || ! current_user_can( 'read_post', $page_id ) || ! current_user_can( 'edit_post', $page_id ) ) {
					return self::error( 'invalid_homepage', 'Homepage and posts-page selections must be published, password-free pages you can read and edit.', 400 );
				}
			}
		}
		global $wp_rewrite;
		$old_permalink = $current['settings']['permalink_structure'];
		$change_permalink = isset( $settings['permalink_structure'] ) && $settings['permalink_structure'] !== $old_permalink;
		if ( $change_permalink && ( ! ( $wp_rewrite instanceof \WP_Rewrite ) || ! $old_permalink || ! $wp_rewrite->using_mod_rewrite_permalinks() ) ) {
			return self::error( 'unsupported_permalink_transition', 'Permalink updates require existing non-index pretty routing. Changing plain or index.php routing would change the MCP OAuth resource URL; configure that transition in WordPress and reconnect separately.', 400 );
		}

		// All values and relationships are validated before any option writes begin.
		// Keep the exact OAuth resource stable even if an installed plugin filters REST URLs.
		if ( $change_permalink ) {
			$resource_url = Plugin::resource_url();
			$wp_rewrite->set_permalink_structure( $settings['permalink_structure'] );
			if ( get_option( 'permalink_structure' ) !== $settings['permalink_structure'] || Plugin::resource_url() !== $resource_url ) {
				$wp_rewrite->set_permalink_structure( $old_permalink );
				$wp_rewrite->flush_rules( false );
				return self::error( 'permalink_update_rejected', 'The permalink change was rejected or would change the MCP resource URL. The original permalink structure was restored.', 409 );
			}
		}
		$additional = self::additional_settings_defaults();
		$rest_settings = array_diff_key( $settings, $additional );
		if ( $rest_settings ) {
			$response = self::request( 'POST', '/wp/v2/settings', array_merge( $rest_settings, array( '_fields' => implode( ',', array_keys( self::settings_properties() ) ) ) ) );
			if ( is_wp_error( $response ) ) {
				if ( $change_permalink ) {
					$wp_rewrite->set_permalink_structure( $old_permalink );
					$wp_rewrite->flush_rules( false );
				}
				return $response;
			}
		}
		foreach ( array_intersect_key( $settings, $additional ) as $name => $value ) {
			if ( 'permalink_structure' !== $name ) {
				// update_option applies WordPress option sanitization and standard option hooks.
				update_option( $name, is_bool( $value ) ? (int) $value : $value );
			}
		}
		if ( $change_permalink ) {
			$wp_rewrite->flush_rules( false );
		}
		$saved = self::get_settings();
		if ( is_wp_error( $saved ) ) {
			return $saved;
		}
		$unapplied = array();
		foreach ( $settings as $name => $value ) {
			// Core sanitizes free-form text (for example, HTML entities in the title).
			// Exact equality is meaningful for all other bounded options and enums.
			if ( in_array( $name, array( 'title', 'description', 'date_format', 'time_format' ), true ) ) {
				continue;
			}
			if ( ! array_key_exists( $name, $saved['settings'] ) || $saved['settings'][ $name ] !== $value ) {
				$unapplied[] = $name;
			}
		}
		if ( $unapplied ) {
			return new \WP_Error( 'kodanote_mcp_settings_update_incomplete', 'WordPress did not retain every requested setting. Other supplied settings may have changed. Read get_site_settings before retrying or reverting.', array( 'status' => 409, 'unapplied_settings' => $unapplied ) );
		}
		return $saved;
	}

	private static function list_plugins( array $input ) {
		$response = self::request( 'GET', '/wp/v2/plugins', array( '_fields' => 'plugin,name,version,status' ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		// The core plugin endpoint has no pagination. Bound the MCP output ourselves.
		$page = $input['page'] ?? 1;
		$per_page = $input['per_page'] ?? 20;
		$all = $response->get_data();
		$items = array();
		foreach ( array_slice( $all, ( $page - 1 ) * $per_page, $per_page ) as $plugin ) {
			$items[] = array(
				'id' => sanitize_text_field( $plugin['plugin'] ?? '' ),
				'name' => sanitize_text_field( $plugin['name'] ?? '' ),
				'version' => sanitize_text_field( $plugin['version'] ?? '' ),
				'status' => sanitize_text_field( $plugin['status'] ?? '' ),
			);
		}
		return array( 'items' => $items, 'page' => $page, 'has_more' => $page * $per_page < count( $all ) );
	}

	private static function list_users( array $input ) {
		$params = array(
			'context' => 'view', '_fields' => 'id,name,slug',
			'search' => $input['search'] ?? '',
			'page' => $input['page'] ?? 1, 'per_page' => $input['per_page'] ?? 20,
			'orderby' => 'id', 'order' => 'asc',
		);
		$response = self::request( 'GET', '/wp/v2/users', $params );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$items = array();
		foreach ( $response->get_data() as $item ) {
			$user = get_userdata( $item['id'] );
			if ( ! $user ) {
				continue;
			}
			// list_users permits viewing roles without edit_user; never return the full WP_User object.
			$items[] = array( 'id' => (int) $item['id'], 'display_name' => (string) ( $item['name'] ?? '' ), 'slug' => (string) ( $item['slug'] ?? '' ), 'roles' => array_values( $user->roles ) );
		}
		return self::page( $items, $params['page'], $response );
	}

	private static function list_media( array $input ) {
		$params = array(
			'context' => 'edit', '_fields' => self::media_fields(),
			'search' => $input['search'] ?? '',
			'page' => $input['page'] ?? 1, 'per_page' => $input['per_page'] ?? 20,
			'orderby' => $input['orderby'] ?? 'date', 'order' => $input['order'] ?? 'desc',
		);
		$attachment_type = get_post_type_object( 'attachment' );
		if ( ! $attachment_type || ! current_user_can( $attachment_type->cap->edit_others_posts ) ) {
			$params['author'] = get_current_user_id();
		}
		$response = self::request( 'GET', '/wp/v2/media', $params );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$items = array();
		foreach ( $response->get_data() as $item ) {
			if ( ! is_wp_error( self::editable_attachment( $item['id'] ) ) ) {
				$items[] = self::format_media( $item );
			}
		}
		return self::page( $items, $params['page'], $response );
	}

	private static function get_media( int $id ) {
		$attachment = self::editable_attachment( $id );
		if ( is_wp_error( $attachment ) ) {
			return $attachment;
		}
		$response = self::request( 'GET', '/wp/v2/media/' . $id, array( 'context' => 'edit', '_fields' => self::media_fields() ) );
		return is_wp_error( $response ) ? $response : self::format_media( $response->get_data() );
	}

	private static function update_media( array $input ) {
		$current = self::get_media( $input['id'] );
		if ( is_wp_error( $current ) ) {
			return $current;
		}
		if ( ! hash_equals( $current['version'], $input['version'] ) ) {
			return self::error( 'conflict', 'The attachment changed since it was read. Read it again and review the metadata before retrying.', 409 );
		}
		$params = array_intersect_key( $input, array_flip( array( 'title', 'caption', 'description', 'alt_text', 'parent' ) ) );
		if ( ! $params ) {
			return self::error( 'empty_update', 'Supply at least one media metadata field to update.', 400 );
		}
		if ( isset( $params['parent'] ) ) {
			if ( $params['parent'] ) {
				$parent = get_post( $params['parent'] );
				if ( ! $parent || ! in_array( $parent->post_type, array( 'post', 'page' ), true ) || ! current_user_can( 'read_post', $parent->ID ) || ! current_user_can( 'edit_post', $parent->ID ) ) {
					return self::error( 'invalid_parent', 'The parent must be an existing post or page you may read and edit.', 403 );
				}
			}
			$params['post'] = $params['parent'];
			unset( $params['parent'] );
		}
		$params['context'] = 'edit';
		$params['_fields'] = self::media_fields();
		$response = self::request( 'POST', '/wp/v2/media/' . $input['id'], $params );
		return is_wp_error( $response ) ? $response : self::format_media( $response->get_data() );
	}

	private static function editable_attachment( int $id ) {
		$post = get_post( $id );
		if ( ! $post || 'attachment' !== $post->post_type ) {
			return self::error( 'not_found', 'No accessible attachment with this ID.', 404 );
		}
		if ( ! current_user_can( 'read_post', $id ) || ! current_user_can( 'edit_post', $id ) ) {
			return self::error( 'forbidden', 'You may not read and edit this attachment.', 403 );
		}
		return $post;
	}

	private static function media_fields(): string {
		return 'id,author,date,modified,modified_gmt,title,caption,description,alt_text,post,media_type,mime_type,source_url';
	}

	private static function format_media( array $item ): array {
		$data = array_intersect_key( $item, array_flip( array( 'id', 'author', 'date', 'modified', 'modified_gmt', 'media_type', 'mime_type', 'source_url' ) ) );
		foreach ( array( 'title', 'caption', 'description' ) as $field ) {
			$data[ $field ] = $item[ $field ]['raw'] ?? '';
		}
		$data['alt_text'] = (string) ( $item['alt_text'] ?? '' );
		$data['parent'] = (int) ( $item['post'] ?? 0 );
		// Text and alt changes are included, even if they occur within the same modified timestamp second.
		$data['version'] = self::fingerprint( array_intersect_key( $data, array_flip( array( 'id', 'modified', 'modified_gmt', 'title', 'caption', 'description', 'alt_text', 'parent' ) ) ) );
		return $data;
	}

	private static function page( array $items, int $page, \WP_REST_Response $response ): array {
		$headers = $response->get_headers();
		return array( 'items' => $items, 'page' => $page, 'has_more' => $page < (int) ( $headers['X-WP-TotalPages'] ?? 0 ) );
	}

	private static function fingerprint( array $data ): string {
		ksort( $data );
		return hash( 'sha256', wp_json_encode( $data ) );
	}

	/** Internal dispatch preserves the core controllers' validation, sanitization and permissions. */
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

	private static function definition( string $name, string $title, string $description, array $properties, array $required, bool $read_only ): array {
		return array(
			'name' => $name, 'title' => $title, 'description' => $description,
			'inputSchema' => self::schema( $properties, $required ),
			'annotations' => array( 'readOnlyHint' => $read_only, 'destructiveHint' => ! $read_only, 'idempotentHint' => $read_only, 'openWorldHint' => false ),
		);
	}
}
