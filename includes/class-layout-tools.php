<?php
namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

/** Targeted block edits preserve the surrounding saved HTML and template structure. */
final class Layout_Tools {
	private const MAX_BLOCKS = 1000;
	private const MAX_DEPTH = 16;
	private const MAX_CONTENT = 500000;

	public static function definitions(): array {
		$target = array(
			'id' => array( 'type' => 'string', 'minLength' => 4, 'maxLength' => 300, 'description' => 'Exact template or part ID returned by list_templates.' ),
			'type' => array( 'type' => 'string', 'enum' => array( 'template', 'template_part' ), 'default' => 'template' ),
		);
		return array(
			self::definition( 'get_layout', 'Inspect template block layout', 'Read saved content and its editable blocks tree with paths and version. Pattern references remain intact. resolved_content and resolved_blocks separately show expanded patterns for inspection; that tree has no editable paths. To customize a pattern, deliberately replace its reference in blocks with resolved markup, then read the new paths. Does not render blocks. Requires edit_theme_options.', $target, array( 'id' ), true ),
			self::definition( 'update_layout', 'Edit template block layout', 'Replace, insert or remove selected blocks within a template, header or footer. Use paths from get_layout.blocks only, never the inspection-only resolved_blocks tree. Untouched pattern references are preserved; replace a pattern reference with expanded markup only when intentionally customizing it. Paths are evaluated sequentially against earlier operations. All operations are validated in memory before one save; changes affect the live site. Supply complete valid block markup including saved HTML.', array_merge( $target, array(
				'version' => array( 'type' => 'string', 'pattern' => '^[a-f0-9]{64}$' ),
				'operations' => array( 'type' => 'array', 'minItems' => 1, 'maxItems' => 50, 'items' => array(
					'type' => 'object', 'additionalProperties' => false, 'required' => array( 'action', 'path' ),
					'properties' => array(
						'action' => array( 'type' => 'string', 'enum' => array( 'replace', 'insert_before', 'insert_after', 'remove' ) ),
						'path' => array( 'type' => 'array', 'minItems' => 1, 'maxItems' => self::MAX_DEPTH, 'items' => array( 'type' => 'integer', 'minimum' => 0, 'maximum' => self::MAX_BLOCKS ) ),
						'content' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => self::MAX_CONTENT, 'description' => 'Required for replace/insert: one or more complete HTML/block fragments. Must be omitted for remove. No PHP.' ),
					),
				) ),
			) ), array( 'id', 'version', 'operations' ), false ),
		);
	}

	public static function required_scope( string $name ): ?string {
		return 'get_layout' === $name ? 'appearance:read' : ( 'update_layout' === $name ? 'appearance:write' : null );
	}
	public static function can_use( string $name ): bool {
		return null !== self::required_scope( $name ) && get_current_user_id() && current_user_can( 'read' ) && current_user_can( 'edit_theme_options' );
	}

	public static function call( string $name, array $input ) {
		if ( ! self::can_use( $name ) ) { return self::error( 'forbidden', 'Your account cannot edit site layouts.', 403 ); }
		foreach ( self::definitions() as $definition ) {
			if ( $definition['name'] === $name ) {
				$valid = rest_validate_value_from_schema( $input, $definition['inputSchema'], 'arguments' );
				if ( is_wp_error( $valid ) ) { return $valid; }
				break;
			}
		}
		$target = array( 'id' => $input['id'], 'type' => $input['type'] ?? 'template' );
		$current = Appearance_Tools::call( 'get_template', $target );
		if ( is_wp_error( $current ) ) { return $current; }
		$blocks = self::parse( $current['content'] );
		if ( is_wp_error( $blocks ) ) { return $blocks; }
		if ( 'get_layout' === $name ) { return self::format( $current, $blocks ); }
		if ( ! hash_equals( $current['version'], $input['version'] ) ) { return self::error( 'conflict', 'The layout changed. Read get_layout again and review before retrying.', 409 ); }
		foreach ( $input['operations'] as $operation ) {
			if ( 'remove' === $operation['action'] ) {
				if ( array_key_exists( 'content', $operation ) ) { return self::error( 'invalid_operation', 'Remove operations must not include content.' ); }
				$replacement = array();
			} else {
				if ( ! isset( $operation['content'] ) || '' === trim( $operation['content'] ) ) { return self::error( 'invalid_operation', 'Insert and replace operations require nonempty content.' ); }
				$replacement = self::parse( $operation['content'], true );
				if ( is_wp_error( $replacement ) ) { return $replacement; }
			}
			$root_fragments = null;
			$result = self::edit( $blocks, $root_fragments, $operation['path'], $operation['action'], $replacement );
			if ( is_wp_error( $result ) ) { return $result; }
			$count = 0;
			$result = self::check_tree( $blocks, 1, $count );
			if ( is_wp_error( $result ) ) { return $result; }
		}
		$content = serialize_blocks( $blocks );
		if ( strlen( $content ) > self::MAX_CONTENT ) { return self::error( 'layout_too_large', 'The resulting layout exceeds 500,000 bytes.' ); }
		$saved = Appearance_Tools::call( 'update_template', $target + array( 'version' => $input['version'], 'content' => $content ) );
		if ( is_wp_error( $saved ) ) { return $saved; }
		// Re-read sanitized saved markup rather than returning the proposed in-memory layout.
		return self::call( 'get_layout', $target );
	}

	private static function parse( string $content, bool $fragment = false ) {
		if ( strlen( $content ) > self::MAX_CONTENT ) { return self::error( 'layout_too_large', 'Layout editing supports up to 500,000 bytes.' ); }
		if ( $fragment && ( str_contains( $content, '<?' ) || str_contains( $content, '?>' ) ) ) { return self::error( 'invalid_markup', 'Use HTML or block markup; PHP is not accepted.' ); }
		// Core's parser recovers from mismatched delimiters; edits should fail instead of silently repairing them.
		$parser = new \WP_Block_Parser();
		$parser->document = $content;
		$parser->offset = 0;
		$stack = array();
		while ( true ) {
			list( $kind, $name, $attributes, $start, $length ) = $parser->next_token();
			if ( 'no-more-tokens' === $kind ) { break; }
			$parser->offset = $start + $length;
			if ( 'block-closer' === $kind ) {
				if ( array_pop( $stack ) !== $name ) { return self::error( 'invalid_markup', 'Block opening and closing delimiters must match.' ); }
			} else {
				if ( ! is_array( $attributes ) ) { return self::error( 'invalid_markup', 'Block attributes must contain valid JSON objects.' ); }
				if ( $fragment && 'core/navigation' === $name && isset( $attributes['ref'] ) ) {
					$menu = is_int( $attributes['ref'] ) && $attributes['ref'] > 0 ? get_post( $attributes['ref'] ) : null;
					if ( ! $menu || 'wp_navigation' !== $menu->post_type || 'publish' !== $menu->post_status || ! current_user_can( 'read_post', $menu->ID ) || ! current_user_can( 'edit_post', $menu->ID ) ) {
						return self::error( 'invalid_navigation_ref', 'Attach a published navigation menu you may read and edit. Publish drafts with update_navigation first.' );
					}
				}
				if ( 'block-opener' === $kind ) { $stack[] = $name; }
			}
		}
		if ( $stack ) { return self::error( 'invalid_markup', 'Close every block delimiter in the layout markup.' ); }
		$blocks = parse_blocks( $content );
		$count = 0;
		$valid = self::check_tree( $blocks, 1, $count );
		return is_wp_error( $valid ) ? $valid : $blocks;
	}

	private static function check_tree( array $blocks, int $depth, int &$count ) {
		if ( $blocks && $depth > self::MAX_DEPTH ) { return self::error( 'layout_too_deep', 'Layout editing supports up to 16 block levels.' ); }
		foreach ( $blocks as $block ) {
			if ( ++$count > self::MAX_BLOCKS ) { return self::error( 'layout_too_large', 'Layout editing supports up to 1,000 blocks.' ); }
			$placeholders = count( array_filter( $block['innerContent'], static function ( $item ) { return null === $item; } ) );
			if ( $placeholders !== count( $block['innerBlocks'] ) ) { return self::error( 'invalid_markup', 'The saved block structure is inconsistent.' ); }
			$valid = self::check_tree( $block['innerBlocks'], $depth + 1, $count );
			if ( is_wp_error( $valid ) ) { return $valid; }
		}
		return true;
	}

	/** Keep the parent's HTML chunks and null child placeholders aligned with innerBlocks. */
	private static function edit( array &$blocks, ?array &$fragments, array $path, string $action, array $replacement ) {
		$index = array_shift( $path );
		if ( ! array_key_exists( $index, $blocks ) ) { return self::error( 'invalid_path', 'A block path does not exist. Paths refer to the result of preceding operations.' ); }
		if ( $path ) { return self::edit( $blocks[ $index ]['innerBlocks'], $blocks[ $index ]['innerContent'], $path, $action, $replacement ); }
		$offset = $index + ( 'insert_after' === $action ? 1 : 0 );
		$remove = in_array( $action, array( 'remove', 'replace' ), true ) ? 1 : 0;
		if ( null !== $fragments ) {
			$positions = array_keys( $fragments, null, true );
			if ( ! isset( $positions[ $index ] ) ) { return self::error( 'invalid_markup', 'The child block has no matching position in its parent markup.' ); }
			$position = $positions[ $index ] + ( 'insert_after' === $action ? 1 : 0 );
			array_splice( $fragments, $position, $remove, array_fill( 0, count( $replacement ), null ) );
		}
		array_splice( $blocks, $offset, $remove, $replacement );
		return true;
	}

	private static function format( array $template, array $blocks ) {
		$resolved_content = $template['resolved_content'] ?? $template['content'];
		$resolved = self::parse( $resolved_content );
		if ( is_wp_error( $resolved ) ) { return $resolved; }
		return array(
			'id' => $template['id'], 'type' => 'wp_template_part' === ( $template['type'] ?? '' ) ? 'template_part' : 'template',
			'title' => $template['title'], 'version' => $template['version'], 'content' => $template['content'],
			'blocks' => self::tree( $blocks ),
			'resolved_content' => $resolved_content,
			'resolved_blocks' => self::tree( $resolved, array(), false ),
			'editing_note' => 'Only paths in blocks are editable. resolved_blocks is an inspection view without editable paths. To customize a pattern, replace its raw pattern reference with the desired expanded markup; untouched references stay intact.',
		);
	}
	private static function tree( array $blocks, array $parent = array(), bool $editable = true ): array {
		$result = array();
		foreach ( $blocks as $index => $block ) {
			$path = array_merge( $parent, array( $index ) );
			$item = array( 'name' => $block['blockName'], 'attributes' => (object) $block['attrs'], 'content' => serialize_block( $block ), 'children' => self::tree( $block['innerBlocks'], $path, $editable ) );
			if ( $editable ) { $item['path'] = $path; }
			$result[] = $item;
		}
		return $result;
	}
	private static function error( string $code, string $message, int $status = 400 ): \WP_Error { return new \WP_Error( 'kodanote_mcp_' . $code, $message, array( 'status' => $status ) ); }
	private static function definition( string $name, string $title, string $description, array $properties, array $required, bool $read ): array {
		return array( 'name' => $name, 'title' => $title, 'description' => $description,
			'inputSchema' => array( 'type' => 'object', 'properties' => $properties, 'required' => $required, 'additionalProperties' => false ),
			'annotations' => array( 'readOnlyHint' => $read, 'destructiveHint' => ! $read, 'idempotentHint' => $read, 'openWorldHint' => false ),
		);
	}
}
