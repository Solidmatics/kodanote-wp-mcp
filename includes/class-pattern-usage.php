<?php
/** Finds where synced patterns are referenced, for MCP tools and the "Used in" admin views. */

namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Pattern_Usage {
	private const COLUMN = 'kodanote_mcp_used_in';

	/** Post types that never hold block content worth reporting. Revisions are excluded by status. */
	private const SKIPPED_TYPES = array( 'attachment', 'nav_menu_item', 'customize_changeset', 'oembed_cache', 'user_request', 'wp_global_styles', 'wp_font_family', 'wp_font_face' );

	public static function boot(): void {
		add_filter( 'manage_wp_block_posts_columns', array( self::class, 'columns' ) );
		add_action( 'manage_wp_block_posts_custom_column', array( self::class, 'column' ), 10, 2 );
		add_action( 'rest_api_init', array( self::class, 'register_routes' ) );
		add_action( 'enqueue_block_editor_assets', array( self::class, 'enqueue_editor_panel' ) );
	}

	public static function is_synced( int $pattern_id ): bool {
		return 'unsynced' !== get_post_meta( $pattern_id, 'wp_pattern_sync_status', true );
	}

	/**
	 * Saved items embedding the pattern through a core/block reference, limited to what
	 * the current user may open. Others are only counted, so an edit's reach stays visible.
	 *
	 * @return array{total:int, items:array, hidden:int, truncated:bool}
	 */
	public static function find( int $pattern_id, int $limit = 50 ): array {
		$visible = array();
		$hidden = 0;
		foreach ( self::referencing_posts( $pattern_id ) as $post ) {
			if ( self::visible( $post ) ) {
				$visible[] = $post;
			} else {
				++$hidden;
			}
		}
		return array(
			'total' => count( $visible ) + $hidden,
			'items' => array_map( array( self::class, 'item' ), array_slice( $visible, 0, $limit ) ),
			'hidden' => $hidden,
			'truncated' => count( $visible ) > $limit,
		);
	}

	/** Pattern IDs referenced anywhere in block markup, including nested blocks. */
	public static function refs_in( string $content ): array {
		if ( false === strpos( $content, '<!-- wp:block ' ) ) {
			return array();
		}
		$refs = array();
		$walk = static function ( array $blocks ) use ( &$walk, &$refs ) {
			foreach ( $blocks as $block ) {
				if ( 'core/block' === ( $block['blockName'] ?? '' ) && isset( $block['attrs']['ref'] ) && is_numeric( $block['attrs']['ref'] ) ) {
					$refs[ (int) $block['attrs']['ref'] ] = true;
				}
				if ( ! empty( $block['innerBlocks'] ) ) {
					$walk( $block['innerBlocks'] );
				}
			}
		};
		$walk( parse_blocks( $content ) );
		return array_keys( $refs );
	}

	/** @return \WP_Post[] */
	private static function referencing_posts( int $pattern_id ): array {
		global $wpdb;
		// The LIKE clauses only narrow the scan; parsing below confirms each reference.
		$types = implode( ',', array_fill( 0, count( self::SKIPPED_TYPES ), '%s' ) );
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT ID, post_content FROM {$wpdb->posts} WHERE post_type NOT IN ($types) AND post_status NOT IN ('trash','auto-draft','inherit') AND ID <> %d AND post_content LIKE %s AND post_content LIKE %s ORDER BY ID ASC",
			array_merge( self::SKIPPED_TYPES, array( $pattern_id, '%' . $wpdb->esc_like( '<!-- wp:block ' ) . '%', '%' . $wpdb->esc_like( '"ref":' . $pattern_id ) . '%' ) )
		) );
		$posts = array();
		foreach ( (array) $rows as $row ) {
			if ( in_array( $pattern_id, self::refs_in( (string) $row->post_content ), true ) ) {
				$post = get_post( (int) $row->ID );
				if ( $post ) {
					$posts[] = $post;
				}
			}
		}
		return $posts;
	}

	/** Items the user may edit, or published public items anyone may read. */
	private static function visible( \WP_Post $post ): bool {
		if ( current_user_can( 'read_post', $post->ID ) && current_user_can( 'edit_post', $post->ID ) ) {
			return true;
		}
		return 'publish' === $post->post_status && '' === $post->post_password && is_post_type_viewable( $post->post_type ) && current_user_can( 'read_post', $post->ID );
	}

	private static function item( \WP_Post $post ): array {
		$type = get_post_type_object( $post->post_type );
		$item = array(
			'id' => $post->ID,
			'type' => $post->post_type,
			'type_label' => $type ? $type->labels->singular_name : $post->post_type,
			'title' => '' !== trim( $post->post_title ) ? $post->post_title : '(no title)',
			'status' => $post->post_status,
		);
		if ( 'publish' === $post->post_status && is_post_type_viewable( $post->post_type ) ) {
			$item['link'] = get_permalink( $post );
		}
		if ( current_user_can( 'edit_post', $post->ID ) ) {
			$edit = get_edit_post_link( $post->ID, 'raw' );
			if ( $edit ) {
				$item['edit_link'] = $edit;
			}
		}
		return $item;
	}

	public static function columns( array $columns ): array {
		$result = array();
		foreach ( $columns as $key => $label ) {
			$result[ $key ] = $label;
			if ( 'title' === $key ) {
				$result[ self::COLUMN ] = 'Used in';
			}
		}
		$result[ self::COLUMN ] = $result[ self::COLUMN ] ?? 'Used in';
		return $result;
	}

	public static function column( string $column, int $post_id ): void {
		if ( self::COLUMN !== $column ) {
			return;
		}
		$usage = self::find( $post_id, 5 );
		if ( ! $usage['total'] ) {
			echo esc_html( self::is_synced( $post_id ) ? 'Not used yet' : 'Not synced. Inserted copies are not tracked.' );
			return;
		}
		$lines = array();
		foreach ( $usage['items'] as $item ) {
			$label = esc_html( $item['title'] ) . ' <span class="description">(' . esc_html( $item['type_label'] ) . ')</span>';
			$href = $item['edit_link'] ?? ( $item['link'] ?? '' );
			$lines[] = $href ? '<a href="' . esc_url( $href ) . '">' . $label . '</a>' : $label;
		}
		$more = $usage['total'] - $usage['hidden'] - count( $usage['items'] );
		if ( $more > 0 ) {
			$lines[] = esc_html( sprintf( 'and %d more', $more ) );
		}
		if ( $usage['hidden'] ) {
			$lines[] = '<span class="description">' . esc_html( sprintf( 1 === $usage['hidden'] ? '%d place you cannot open' : '%d places you cannot open', $usage['hidden'] ) ) . '</span>';
		}
		echo wp_kses_post( implode( '<br>', $lines ) );
	}

	/** Cookie-authenticated route for the editor panel. MCP clients use get_pattern instead. */
	public static function register_routes(): void {
		register_rest_route(
			'kodanote-mcp/v1',
			'/patterns/(?P<id>\d+)/usage',
			array(
				'methods' => 'GET',
				'callback' => static function ( \WP_REST_Request $request ) {
					$id = (int) $request['id'];
					return rest_ensure_response( array( 'id' => $id, 'synced' => self::is_synced( $id ) ) + self::find( $id, 100 ) );
				},
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					$post = get_post( (int) $request['id'] );
					return $post && 'wp_block' === $post->post_type && current_user_can( 'edit_post', $post->ID );
				},
				'args' => array( 'id' => array( 'type' => 'integer', 'minimum' => 1 ) ),
			)
		);
	}

	/** The panel only renders while a pattern is open, in the post editor or the Site Editor. */
	public static function enqueue_editor_panel(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! current_user_can( 'edit_posts' ) || ( $screen && 'site-editor' !== $screen->base && 'wp_block' !== $screen->post_type ) ) {
			return;
		}
		wp_enqueue_script(
			'kodanote-mcp-pattern-usage',
			plugins_url( 'assets/pattern-usage.js', KODANOTE_MCP_FILE ),
			array( 'wp-api-fetch', 'wp-data', 'wp-editor', 'wp-element', 'wp-plugins' ),
			KODANOTE_MCP_VERSION,
			true
		);
	}
}
