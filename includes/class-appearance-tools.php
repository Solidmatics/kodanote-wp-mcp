<?php
/** Theme discovery and bounded Site Editor operations. */

namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Appearance_Tools {

	public static function definitions(): array {
		$version = array( 'type' => 'string', 'pattern' => '^[a-f0-9]{64}$', 'description' => 'The version returned by the most recent get operation. A stale version fails without writing.' );
		$slug = array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 100, 'pattern' => '^[a-z0-9][a-z0-9-]*$' );
		$color = array( 'type' => array( 'string', 'null' ), 'maxLength' => 140, 'pattern' => '^(#[a-fA-F0-9]{3}|#[a-fA-F0-9]{4}|#[a-fA-F0-9]{6}|#[a-fA-F0-9]{8}|var:preset\|color\|[a-z0-9][a-z0-9-]*)$', 'description' => 'Hex color or an existing var:preset|color|slug reference; null removes this user override.' );
		$preset = array_merge( $slug, array( 'type' => array( 'string', 'null' ), 'description' => 'An existing theme or user preset slug; null removes this user override.' ) );
		$type = array( 'type' => 'string', 'enum' => array( 'template', 'template_part' ), 'default' => 'template' );
		$area = array( 'type' => 'string', 'enum' => array( 'header', 'footer', 'uncategorized' ), 'description' => 'Template part area. Only valid when type is template_part.' );
		$length = array( 'type' => array( 'string', 'null' ), 'maxLength' => 18, 'pattern' => '^(0|(?:[0-9]{1,5}(?:\.[0-9]{1,4})?|\.[0-9]{1,4})(?:px|rem|em|%|vw|vh))$', 'description' => 'Nonnegative CSS length in px, rem, em, %, vw, or vh, or 0. Up to five integer and four decimal digits. Null removes this user override.' );
		$padding = self::schema( array( 'top' => $length, 'right' => $length, 'bottom' => $length, 'left' => $length ) );
		$padding['type'] = array( 'object', 'null' );
		$padding['description'] = 'Update only supplied global padding sides; null removes all user padding overrides.';
		$template_id = array( 'type' => 'string', 'minLength' => 4, 'maxLength' => 300, 'description' => 'Exact template ID returned by list_templates, such as twentytwentyfive//index.' );
		return array(
			self::definition( 'get_theme', 'Get active theme', 'Read the active theme, parent theme, supported appearance features, and standard classic-theme editor colors. Custom CSS and arbitrary theme options are not inspected.', array(), array(), true ),
			self::definition( 'get_global_styles', 'Get theme colors and styles', 'Read merged WordPress default, parent/child theme, and user global settings/styles, including color palettes and typography presets. Includes user overrides and a version for updates. Classic themes expose the settings WordPress knows about; arbitrary CSS is not parsed.', array(), array(), true ),
			self::definition( 'update_global_styles', 'Update global colors, typography, layout, and CSS', 'Update only supplied global appearance controls, content/wide widths, block gap, padding, and Additional CSS. Replaces the user palette when supplied; an empty palette removes user palette entries. Preserves other user settings/styles. Changes affect the live site; layout effects depend on theme/block support. Requires edit_theme_options and a theme.json theme. CSS writes or preservation of existing CSS also require edit_css. Read get_global_styles first.', array(
				'version' => $version,
				'palette' => array( 'type' => 'array', 'maxItems' => 100, 'items' => self::schema( array(
					'slug' => $slug,
					'name' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 100 ),
					'color' => array( 'type' => 'string', 'pattern' => '^(#[a-fA-F0-9]{3}|#[a-fA-F0-9]{4}|#[a-fA-F0-9]{6}|#[a-fA-F0-9]{8})$', 'maxLength' => 9 ),
				), array( 'slug', 'name', 'color' ) ) ),
				'background_color' => $color, 'text_color' => $color, 'link_color' => $color,
				'font_family_slug' => $preset, 'font_size_slug' => $preset,
				'content_width' => $length, 'wide_width' => $length, 'block_gap' => $length, 'padding' => $padding,
				'custom_css' => array( 'type' => array( 'string', 'null' ), 'maxLength' => 50000, 'description' => 'Complete replacement for user Additional CSS, up to 50,000 characters. Omit to preserve; an empty string saves empty CSS; null removes the override. Requires edit_css and native WordPress CSS validation.' ),
			), array( 'version' ), false ),
			self::definition( 'list_templates', 'List block templates and parts', 'List block templates or template parts available to the active theme. Requires edit_theme_options. Only database overrides can be changed; theme source files are never written.', array(
				'type' => $type,
				'area' => $area,
				'search' => array( 'type' => 'string', 'maxLength' => 100, 'description' => 'Case-insensitive substring of the template ID, slug, title, or description.' ),
				'page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1 ),
				'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 50, 'default' => 20 ),
			), array(), true ),
			self::definition( 'get_template', 'Get a block template or part', 'Read a block template or part and its version before editing. content preserves saved pattern references; resolved_content is a separate inspection view with registered patterns expanded. Edit content to preserve untouched references. Requires edit_theme_options.', array( 'id' => $template_id, 'type' => $type ), array( 'id' ), true ),
			self::definition( 'create_template', 'Create a block template or part', 'Create a missing block template or header/footer part as a published database record for the active theme. Existing slugs are rejected: use get_template and update_template to edit them. Does not insert the new part into layouts automatically. Theme files are never written. Requires edit_theme_options and block-template support.', array(
				'type' => $type, 'slug' => $slug, 'area' => $area,
				'title' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 1000 ),
				'description' => array( 'type' => 'string', 'maxLength' => 5000 ),
				'content' => array( 'type' => 'string', 'maxLength' => 500000, 'description' => 'Complete HTML / WordPress block markup. PHP is not accepted.' ),
			), array( 'slug', 'title', 'content' ), false ),
			self::definition( 'update_template', 'Update a block template or part', 'Save supplied title, description, or complete block markup as a database override through the WordPress Site Editor controller. Affects the live site; creates an override for a theme template without editing theme files. Requires edit_theme_options and the current version from get_template.', array(
				'id' => $template_id, 'type' => $type, 'version' => $version,
				'area' => $area,
				'title' => array( 'type' => 'string', 'maxLength' => 1000 ),
				'description' => array( 'type' => 'string', 'maxLength' => 5000 ),
				'content' => array( 'type' => 'string', 'maxLength' => 500000, 'description' => 'Complete replacement HTML / WordPress block markup. PHP is not accepted.' ),
			), array( 'id', 'version' ), false ),
		);
	}

	public static function required_scope( string $name ): ?string {
		if ( in_array( $name, array( 'get_theme', 'get_global_styles', 'list_templates', 'get_template' ), true ) ) {
			return 'appearance:read';
		}
		return in_array( $name, array( 'update_global_styles', 'create_template', 'update_template' ), true ) ? 'appearance:write' : null;
	}

	public static function can_use( string $name ): bool {
		if ( ! self::required_scope( $name ) || ! get_current_user_id() || ! current_user_can( 'read' ) ) {
			return false;
		}
		if ( in_array( $name, array( 'get_theme', 'get_global_styles' ), true ) ) {
			return current_user_can( 'edit_posts' ) || current_user_can( 'edit_pages' ) || current_user_can( 'edit_theme_options' );
		}
		return current_user_can( 'edit_theme_options' );
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
			return self::error( 'unknown_tool', 'Unknown appearance tool.', 400 );
		}
		$valid = rest_validate_value_from_schema( $input, $definition['inputSchema'], 'arguments' );
		if ( is_wp_error( $valid ) ) {
			return $valid;
		}
		if ( ! self::can_use( $name ) ) {
			return self::error( 'forbidden', 'The connected WordPress user does not have permission for this appearance tool.', 403 );
		}
		switch ( $name ) {
			case 'get_theme':
				return self::theme();
			case 'get_global_styles':
				return self::global_styles();
			case 'update_global_styles':
				return self::update_global_styles( $input );
			case 'list_templates':
				return self::list_templates( $input );
			case 'get_template':
				return self::get_template( $input );
			case 'create_template':
				return self::create_template( $input );
			case 'update_template':
				return self::update_template( $input );
		}
		return self::error( 'unknown_tool', 'Unknown appearance tool.', 400 );
	}

	private static function theme(): array {
		$theme = wp_get_theme();
		$parent = $theme->parent();
		$palette = get_theme_support( 'editor-color-palette' );
		return array(
			'name' => $theme->get( 'Name' ), 'stylesheet' => $theme->get_stylesheet(), 'version' => $theme->get( 'Version' ),
			'parent' => $parent ? array( 'name' => $parent->get( 'Name' ), 'stylesheet' => $parent->get_stylesheet(), 'version' => $parent->get( 'Version' ) ) : null,
			'is_block_theme' => wp_is_block_theme(), 'has_theme_json' => wp_theme_has_theme_json(),
			'supports' => array(
				'block_templates' => current_theme_supports( 'block-templates' ),
				'editor_styles' => current_theme_supports( 'editor-styles' ),
				'custom_colors' => ! current_theme_supports( 'disable-custom-colors' ),
			),
			'legacy_colors' => array(
				'editor_palette' => is_array( $palette ) ? ( $palette[0] ?? array() ) : array(),
				'background_color' => get_theme_mod( 'background_color', '' ),
				'header_textcolor' => get_theme_mod( 'header_textcolor', '' ),
			),
		);
	}

	/** Reading never creates a wp_global_styles post. */
	private static function global_styles(): array {
		$record = \WP_Theme_JSON_Resolver::get_user_data_from_wp_global_styles( wp_get_theme(), false );
		$user = \WP_Theme_JSON_Resolver::get_user_data()->get_raw_data();
		return array(
			'theme' => self::theme(),
			'settings' => wp_get_global_settings(), 'styles' => wp_get_global_styles(),
			'user' => array(
				'id' => (int) ( $record['ID'] ?? 0 ), 'modified' => $record['post_modified_gmt'] ?? null,
				'settings' => $user['settings'] ?? array(), 'styles' => $user['styles'] ?? array(),
			),
			'version' => self::global_styles_version( $record ),
			'writable' => current_user_can( 'edit_theme_options' ) && wp_theme_has_theme_json(),
			'css_writable' => current_user_can( 'edit_theme_options' ) && current_user_can( 'edit_css' ) && wp_theme_has_theme_json(),
		);
	}

	private static function global_styles_version( array $record ): string {
		return hash( 'sha256', wp_json_encode( array( get_stylesheet(), $record['ID'] ?? 0, $record['post_modified_gmt'] ?? '', $record['post_content'] ?? '' ) ) );
	}

	/** Detect CSS that core would otherwise strip when saving without edit_css. */
	public static function has_custom_css( array $styles ): bool {
		if ( array_key_exists( 'css', $styles ) ) {
			return true;
		}
		foreach ( $styles as $value ) {
			if ( is_array( $value ) && self::has_custom_css( $value ) ) {
				return true;
			}
		}
		return false;
	}

	/** Refuse writes when core's permission-dependent filter would discard configuration. */
	public static function validate_global_styles_preservation( array $settings, array $styles ) {
		if ( current_user_can( 'unfiltered_html' ) ) {
			return true;
		}
		$config = array( 'version' => \WP_Theme_JSON::LATEST_SCHEMA, 'isGlobalStylesUserThemeJSON' => true, 'settings' => $settings, 'styles' => $styles );
		$filtered = json_decode( wp_unslash( wp_filter_global_styles_post( wp_slash( wp_json_encode( $config ) ) ) ), true );
		$sort = static function ( $value ) use ( &$sort ) {
			if ( ! is_array( $value ) ) { return $value; }
			if ( ! array_is_list( $value ) ) { ksort( $value ); }
			return array_map( $sort, $value );
		};
		$expected = array( 'settings' => $settings, 'styles' => $styles );
		$actual = is_array( $filtered ) ? array( 'settings' => $filtered['settings'] ?? array(), 'styles' => $filtered['styles'] ?? array() ) : null;
		if ( wp_json_encode( $sort( $expected ) ) !== wp_json_encode( $sort( $actual ) ) ) {
			return self::error( 'global_styles_filtered', 'WordPress would filter this global styles configuration with your current permissions. No global styles were changed.', 403 );
		}
		return true;
	}

	/** Use core validation before a missing user styles record could be created. */
	private static function validate_custom_css( string $css ) {
		$controller = new class() extends \WP_REST_Global_Styles_Controller {
			public function validate_css_input( string $css ) {
				return $this->validate_custom_css( $css );
			}
		};
		return $controller->validate_css_input( $css );
	}

	/** Patch only bounded controls, then let the core controller validate and save. */
	private static function update_global_styles( array $input ) {
		if ( ! wp_theme_has_theme_json() ) {
			return self::error( 'unsupported_theme', 'Global appearance updates require a theme with theme.json support.', 400 );
		}
		if ( 1 === count( $input ) ) {
			return self::error( 'empty_update', 'Supply at least one appearance control to update.', 400 );
		}
		$record = \WP_Theme_JSON_Resolver::get_user_data_from_wp_global_styles( wp_get_theme(), false );
		if ( ! hash_equals( self::global_styles_version( $record ), $input['version'] ) ) {
			return self::conflict();
		}
		$config = isset( $record['post_content'] ) ? json_decode( $record['post_content'], true ) : array();
		if ( ! is_array( $config ) || ( $record && empty( $config['isGlobalStylesUserThemeJSON'] ) ) ) {
			return self::error( 'invalid_global_styles', 'The existing global styles record is invalid and cannot safely be updated.', 409 );
		}
		$settings = $config['settings'] ?? array();
		$styles = $config['styles'] ?? array();
		if ( ! is_array( $settings ) || ! is_array( $styles ) ) {
			return self::error( 'invalid_global_styles', 'The existing settings or styles are invalid and cannot safely be updated.', 409 );
		}
		$css_supplied = array_key_exists( 'custom_css', $input );
		if ( ! current_user_can( 'edit_css' ) && ( $css_supplied || self::has_custom_css( $styles ) ) ) {
			return self::error( 'forbidden', 'Editing or preserving Additional CSS requires the edit_css capability. No global styles were changed.', 403 );
		}
		if ( $css_supplied ) {
			if ( null !== $input['custom_css'] ) {
				$valid = self::validate_custom_css( $input['custom_css'] );
				if ( is_wp_error( $valid ) ) {
					return $valid;
				}
			}
			self::set_path( $styles, array( 'css' ), $input['custom_css'] );
		}
		$effective_settings = wp_get_global_settings();
		if ( array_key_exists( 'palette', $input ) ) {
			$slugs = array_column( $input['palette'], 'slug' );
			if ( count( $slugs ) !== count( array_unique( $slugs ) ) ) {
				return self::error( 'invalid_palette', 'Palette slugs must be unique.', 400 );
			}
			foreach ( $input['palette'] as &$entry ) {
				$entry['name'] = sanitize_text_field( $entry['name'] );
				if ( '' === trim( $entry['name'] ) ) {
					return self::error( 'invalid_palette', 'Palette names must contain readable text.', 400 );
				}
			}
			unset( $entry );
			self::set_path( $settings, array( 'color', 'palette' ), $input['palette'] ? $input['palette'] : null );
			$effective_settings['color']['palette']['custom'] = $input['palette'];
		}
		$controls = array(
			'background_color' => array( 'color', 'background' ),
			'text_color' => array( 'color', 'text' ),
			'link_color' => array( 'elements', 'link', 'color', 'text' ),
			'font_family_slug' => array( 'typography', 'fontFamily' ),
			'font_size_slug' => array( 'typography', 'fontSize' ),
		);
		foreach ( $controls as $control => $path ) {
			if ( ! array_key_exists( $control, $input ) ) {
				continue;
			}
			$value = $input[ $control ];
			if ( null !== $value && in_array( $control, array( 'font_family_slug', 'font_size_slug' ), true ) ) {
				$family = 'font_family_slug' === $control;
				$presets = $effective_settings['typography'][ $family ? 'fontFamilies' : 'fontSizes' ] ?? array();
				if ( ! self::has_preset( $presets, $value ) ) {
					return self::error( 'invalid_preset', 'The requested typography preset is not available in the active theme settings.', 400 );
				}
				$value = 'var:preset|' . ( $family ? 'font-family' : 'font-size' ) . '|' . $value;
			} elseif ( null !== $value && 0 === strpos( $value, 'var:preset|color|' ) && ! self::has_preset( $effective_settings['color']['palette'] ?? array(), substr( $value, 17 ) ) ) {
				return self::error( 'invalid_preset', 'The requested color preset does not exist in the resulting palette.', 400 );
			}
			self::set_path( $styles, $path, $value );
		}
		foreach ( array( 'content_width' => 'contentSize', 'wide_width' => 'wideSize' ) as $control => $property ) {
			if ( array_key_exists( $control, $input ) ) {
				self::set_path( $settings, array( 'layout', $property ), $input[ $control ] );
			}
		}
		if ( array_key_exists( 'block_gap', $input ) ) {
			self::set_path( $styles, array( 'spacing', 'blockGap' ), $input['block_gap'] );
		}
		if ( array_key_exists( 'padding', $input ) ) {
			if ( null === $input['padding'] ) {
				self::set_path( $styles, array( 'spacing', 'padding' ), null );
			} else {
				if ( ! $input['padding'] ) {
					return self::error( 'empty_update', 'Supply at least one padding side, or null to reset all user padding.', 400 );
				}
				// Expand scalar/shorthand padding first so an update preserves the other sides.
				$existing_padding = $styles['spacing']['padding'] ?? null;
				if ( is_string( $existing_padding ) ) {
					$expanded_padding = self::expand_padding( $existing_padding );
					if ( null === $expanded_padding ) {
						return self::error( 'invalid_global_styles', 'Existing padding cannot be safely expanded into sides. Reset padding to null before replacing it.', 409 );
					}
					$styles['spacing']['padding'] = $expanded_padding;
				}
				foreach ( $input['padding'] as $side => $value ) {
					self::set_path( $styles, array( 'spacing', 'padding', $side ), $value );
				}
			}
		}
		$preserved = self::validate_global_styles_preservation( $settings, $styles );
		if ( is_wp_error( $preserved ) ) {
			return $preserved;
		}
		if ( ! $record ) {
			$record = \WP_Theme_JSON_Resolver::get_user_data_from_wp_global_styles( wp_get_theme(), true );
			if ( empty( $record['ID'] ) ) {
				return self::error( 'global_styles_unavailable', 'WordPress could not create a user global styles record.', 500 );
			}
		}
		$response = self::request( 'POST', '/wp/v2/global-styles/' . (int) $record['ID'], array( 'context' => 'edit', 'settings' => $settings, 'styles' => $styles ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		wp_clean_theme_json_cache();
		return self::global_styles();
	}

	/** Expand CSS padding shorthand without splitting spaces inside calc()/clamp(). */
	private static function expand_padding( string $padding ): ?array {
		$values = array();
		$token = '';
		$depth = 0;
		foreach ( str_split( trim( $padding ) ) as $character ) {
			if ( '(' === $character ) {
				++$depth;
			} elseif ( ')' === $character ) {
				--$depth;
				if ( $depth < 0 ) {
					return null;
				}
			}
			if ( 0 === $depth && false !== strpos( " \t\r\n\f", $character ) ) {
				if ( '' !== $token ) {
					$values[] = $token;
					$token = '';
				}
			} else {
				$token .= $character;
			}
		}
		if ( '' !== $token ) {
			$values[] = $token;
		}
		if ( 0 !== $depth || ! $values || count( $values ) > 4 ) {
			return null;
		}
		return array( 'top' => $values[0], 'right' => $values[1] ?? $values[0], 'bottom' => $values[2] ?? $values[0], 'left' => $values[3] ?? $values[1] ?? $values[0] );
	}

	/** WordPress presets can be a flat list or grouped by default/theme/custom. */
	private static function has_preset( array $presets, string $slug ): bool {
		foreach ( $presets as $preset ) {
			if ( is_array( $preset ) && ( ( isset( $preset['slug'] ) && $preset['slug'] === $slug ) || self::has_preset( $preset, $slug ) ) ) {
				return true;
			}
		}
		return false;
	}

	private static function set_path( array &$data, array $path, $value ): void {
		$key = array_shift( $path );
		if ( ! $path ) {
			if ( null === $value ) {
				unset( $data[ $key ] );
			} else {
				$data[ $key ] = $value;
			}
			return;
		}
		if ( ! isset( $data[ $key ] ) || ! is_array( $data[ $key ] ) ) {
			$data[ $key ] = array();
		}
		self::set_path( $data[ $key ], $path, $value );
		if ( ! $data[ $key ] ) {
			unset( $data[ $key ] );
		}
	}

	private static function list_templates( array $input ) {
		if ( ! current_theme_supports( 'block-templates' ) ) {
			return self::error( 'unsupported_theme', 'The active theme does not support block templates.', 400 );
		}
		if ( isset( $input['area'] ) && 'template_part' !== ( $input['type'] ?? 'template' ) ) {
			return self::error( 'invalid_template_area', 'The area filter is only valid for template_part.', 400 );
		}
		$params = array( 'context' => 'edit' );
		if ( isset( $input['area'] ) ) {
			$params['area'] = $input['area'];
		}
		$response = self::request( 'GET', self::template_route( $input ), $params );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$items = $response->get_data();
		if ( isset( $input['search'] ) && '' !== $input['search'] ) {
			$items = array_values( array_filter( $items, static function ( $item ) use ( $input ) {
				$searchable = implode( ' ', array( $item['id'] ?? '', $item['slug'] ?? '', $item['title']['raw'] ?? '', $item['description'] ?? '' ) );
				return false !== stripos( $searchable, $input['search'] );
			} ) );
		}
		usort( $items, static function ( $a, $b ) { return strcmp( $a['id'], $b['id'] ); } );
		$page = $input['page'] ?? 1;
		$per_page = $input['per_page'] ?? 20;
		$selected = array_slice( $items, ( $page - 1 ) * $per_page, $per_page );
		$formatted = array();
		foreach ( $selected as $item ) {
			$template = self::format_template( $item, false );
			if ( is_wp_error( $template ) ) {
				return $template;
			}
			$formatted[] = $template;
		}
		return array(
			'items' => $formatted,
			'page' => $page, 'total' => count( $items ), 'has_more' => $page * $per_page < count( $items ),
		);
	}

	private static function get_template( array $input ) {
		if ( ! current_theme_supports( 'block-templates' ) ) {
			return self::error( 'unsupported_theme', 'The active theme does not support block templates.', 400 );
		}
		// Use exact IDs, never paths. Encode each route segment independently.
		if ( ! preg_match( '~^[^<>?"\\\\|\x00-\x1f]+//(?:[a-zA-Z0-9_\-]|%[a-fA-F0-9]{2})+$~D', $input['id'] ) || false !== strpos( $input['id'], '..' ) ) {
			return self::error( 'invalid_template_id', 'Use an exact template ID from list_templates.', 400 );
		}
		$route = self::template_route( $input ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $input['id'] ) ) );
		$response = self::request( 'GET', $route, array( 'context' => 'edit' ) );
		return is_wp_error( $response ) ? $response : self::format_template( $response->get_data(), true );
	}

	private static function update_template( array $input ) {
		if ( isset( $input['area'] ) && 'template_part' !== ( $input['type'] ?? 'template' ) ) {
			return self::error( 'invalid_template_area', 'The area setting is only valid for template_part.', 400 );
		}
		$current = self::get_template( $input );
		if ( is_wp_error( $current ) ) {
			return $current;
		}
		if ( ! hash_equals( $current['version'], $input['version'] ) ) {
			return self::conflict();
		}
		$params = array_intersect_key( $input, array_flip( array( 'title', 'description', 'content', 'area' ) ) );
		if ( ! $params ) {
			return self::error( 'empty_update', 'Supply title, description, content, or a template part area to update.', 400 );
		}
		if ( isset( $params['content'] ) && ( false !== strpos( $params['content'], '<?' ) || false !== strpos( $params['content'], '?>' ) ) ) {
			return self::error( 'invalid_template_content', 'Template content must be HTML or block markup, not PHP.', 400 );
		}
		$params['context'] = 'edit';
		$route = self::template_route( $input ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $input['id'] ) ) );
		$response = self::request( 'POST', $route, $params );
		return is_wp_error( $response ) ? $response : self::format_template( $response->get_data(), true );
	}

	private static function create_template( array $input ) {
		if ( ! current_theme_supports( 'block-templates' ) ) {
			return self::error( 'unsupported_theme', 'The active theme does not support block templates.', 400 );
		}
		if ( sanitize_title( $input['slug'] ) !== $input['slug'] ) {
			return self::error( 'invalid_template_slug', 'Use a lowercase slug with letters, numbers, and internal hyphens that WordPress will preserve unchanged.', 400 );
		}
		$is_part = 'template_part' === ( $input['type'] ?? 'template' );
		if ( isset( $input['area'] ) && ! $is_part ) {
			return self::error( 'invalid_template_area', 'The area setting is only valid for template_part.', 400 );
		}
		if ( false !== strpos( $input['content'], '<?' ) || false !== strpos( $input['content'], '?>' ) ) {
			return self::error( 'invalid_template_content', 'Template content must be HTML or block markup, not PHP.', 400 );
		}
		if ( '' === trim( wp_strip_all_tags( $input['title'] ) ) ) {
			return self::error( 'invalid_template_title', 'The template title must contain readable text.', 400 );
		}
		$post_type = $is_part ? 'wp_template_part' : 'wp_template';
		$id = get_stylesheet() . '//' . $input['slug'];
		// Check published theme/parent/plugin templates and all database statuses before creating.
		// Core otherwise silently adjusts duplicate slugs, making the requested ID ambiguous.
		if ( get_block_template( $id, $post_type ) || get_block_templates( array( 'slug__in' => array( $input['slug'] ) ), $post_type ) ) {
			return self::error( 'template_exists', 'A template with this slug already exists. Read it with get_template and use update_template with its version.', 409 );
		}
		$params = array_intersect_key( $input, array_flip( array( 'slug', 'title', 'description', 'content', 'area' ) ) );
		$params['context'] = 'edit';
		$params['theme'] = get_stylesheet();
		$response = self::request( 'POST', self::template_route( $input ), $params );
		return is_wp_error( $response ) ? $response : self::format_template( $response->get_data(), true );
	}

	private static function template_route( array $input ): string {
		return '/wp/v2/' . ( 'template_part' === ( $input['type'] ?? 'template' ) ? 'template-parts' : 'templates' );
	}

	/** Native REST checks permission first, but its content.raw expands theme patterns. */
	private static function format_template( array $item, bool $full ) {
		$type = 'wp_template_part' === ( $item['type'] ?? '' ) ? 'wp_template_part' : 'wp_template';
		$source = get_block_template( $item['id'], $type );
		if ( ! $source || ! isset( $source->content ) || ! is_string( $source->content ) ) {
			return self::error( 'template_unavailable', 'The saved template is no longer available. Read the template again before editing.', 409 );
		}
		$data = array_intersect_key( $item, array_flip( array( 'id', 'theme', 'slug', 'type', 'source', 'origin', 'description', 'status', 'wp_id', 'has_theme_file', 'area', 'modified' ) ) );
		$data['title'] = $item['title']['raw'] ?? '';
		$data['version'] = hash( 'sha256', wp_json_encode( array( get_stylesheet(), $data, $source->content ) ) );
		if ( $full ) {
			$data['content'] = $source->content;
			$data['resolved_content'] = $item['content']['raw'] ?? '';
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

	private static function conflict(): \WP_Error {
		return self::error( 'version_conflict', 'Appearance data changed after it was read. Read it again and reapply your changes to the new version.', 409 );
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
			'name' => $name, 'title' => $title, 'description' => $description, 'inputSchema' => self::schema( $properties, $required ),
			'annotations' => array( 'readOnlyHint' => $read_only, 'destructiveHint' => ! $read_only, 'idempotentHint' => $read_only, 'openWorldHint' => false ),
		);
	}
}
