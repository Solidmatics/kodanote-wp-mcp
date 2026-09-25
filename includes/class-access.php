<?php
namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

/** OAuth delegation is bounded by live WordPress capabilities, including custom roles. */
final class Access {
	public static function scopes(): array {
		return array(
			'content:read' => array( 'label' => 'Read content', 'description' => 'Read posts, pages, categories and tags your account may access.' ),
			'content:write' => array( 'label' => 'Edit content', 'description' => 'Create, edit, publish and trash content within your WordPress permissions.' ),
			'appearance:read' => array( 'label' => 'Read appearance', 'description' => 'Read theme colors, typography and styles; inspect templates, headers, footers, navigation and block layouts when your account can edit themes.' ),
			'appearance:write' => array( 'label' => 'Edit appearance', 'description' => 'Change global colors, typography and spacing; create or edit templates, headers, footers, navigation and block layouts. Published changes affect the live site.' ),
			'media:read' => array( 'label' => 'Read media', 'description' => 'Read media library items your account may edit.' ),
			'media:write' => array( 'label' => 'Edit media', 'description' => 'Change media titles, descriptions, captions, alternative text and parent content.' ),
			'settings:read' => array( 'label' => 'Read site settings', 'description' => 'Read supported general, homepage, blog, permalink, feed, discussion and media size settings.' ),
			'settings:write' => array( 'label' => 'Edit site settings', 'description' => 'Change supported general, homepage, blog, permalink, feed, discussion and media size settings. Permalink changes alter public content URLs. These changes affect the live site.' ),
			'plugins:read' => array( 'label' => 'List plugins', 'description' => 'Read installed plugin names, versions and activation status.' ),
			'users:read' => array( 'label' => 'List users', 'description' => 'Read user IDs, public display names, slugs and assigned roles.' ),
			'audit:read' => array( 'label' => 'Read MCP audit history', 'description' => 'Read MCP mutation history and saved before/after values, including private content snapshots. Requires site administration permission.' ),
			'audit:write' => array( 'label' => 'Undo supported MCP changes', 'description' => 'Restore supported logged edits when the affected data has not changed. Also requires the original operation\'s write permission and scope. Undo is itself logged.' ),
		);
	}

	public static function can_scope( string $scope, ?int $user_id = null ): bool {
		$id = $user_id ?? get_current_user_id();
		if ( ! $id || ! user_can( $id, 'read' ) ) { return false; }
		$content = user_can( $id, 'edit_posts' ) || user_can( $id, 'edit_pages' );
		switch ( $scope ) {
			case 'content:read': case 'content:write':
				if ( $content ) { return true; }
				foreach ( array( 'post', 'page' ) as $type ) {
					$pto = get_post_type_object( $type );
					if ( $pto && ( user_can( $id, $pto->cap->create_posts ) || user_can( $id, $pto->cap->delete_posts ) ) ) { return true; }
				}
				foreach ( array( 'category', 'post_tag' ) as $name ) {
					$tax = get_taxonomy( $name );
					if ( $tax && ( user_can( $id, $tax->cap->assign_terms ) || user_can( $id, $tax->cap->edit_terms ) ) ) { return true; }
				}
				return false;
			case 'appearance:read': return $content || user_can( $id, 'edit_theme_options' );
			case 'appearance:write': return user_can( $id, 'edit_theme_options' );
			case 'media:read': case 'media:write': return user_can( $id, 'upload_files' );
			case 'settings:read': case 'settings:write': return user_can( $id, 'manage_options' );
			case 'plugins:read': return user_can( $id, 'activate_plugins' );
			case 'users:read': return user_can( $id, 'list_users' );
			case 'audit:read': case 'audit:write': return user_can( $id, 'manage_options' );
		}
		return false;
	}

	public static function available_scopes( ?int $user_id = null ): array {
		return array_values( array_filter( array_keys( self::scopes() ), static function ( $scope ) use ( $user_id ) { return self::can_scope( $scope, $user_id ); } ) );
	}

	/** Every write scope also delegates its corresponding read scope. */
	public static function normalize( string $scope ): ?string {
		$requested = array_values( array_unique( preg_split( '/ +/', trim( $scope ), -1, PREG_SPLIT_NO_EMPTY ) ) );
		if ( ! $requested || array_diff( $requested, array_keys( self::scopes() ) ) ) { return null; }
		foreach ( $requested as $item ) {
			if ( str_ends_with( $item, ':write' ) ) { $requested[] = substr( $item, 0, -6 ) . ':read'; }
		}
		return implode( ' ', array_intersect( array_keys( self::scopes() ), $requested ) );
	}

	public static function permitted( string $scope, ?int $user_id = null ): string {
		return implode( ' ', array_intersect( explode( ' ', $scope ), self::available_scopes( $user_id ) ) );
	}

	public static function read_only( string $scope ): string {
		return implode( ' ', array_filter( explode( ' ', $scope ), static function ( $item ) { return str_ends_with( $item, ':read' ); } ) );
	}

	public static function field_name( string $scope ): string { return 'scope_' . str_replace( ':', '_', $scope ); }
}
