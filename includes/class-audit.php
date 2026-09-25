<?php
/** Bounded mutation history and permission-preserving, drift-checked restoration. */

namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Audit {
	private const SCHEMA = '1';
	private const MAX_PAYLOAD = 2097152;
	private const RETENTION_DAYS = 90;
	private static $grant = array();
	private static $active_entry = 0;

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'kodanote_mcp_audit';
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table = self::table();
		$collation = $wpdb->get_charset_collate();
		dbDelta( "CREATE TABLE $table (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			user_id bigint(20) unsigned NOT NULL,
			client_id varchar(128) NOT NULL DEFAULT '',
			tool varchar(64) NOT NULL,
			target varchar(191) NOT NULL DEFAULT '',
			status varchar(24) NOT NULL DEFAULT 'pending',
			reversible tinyint(1) NOT NULL DEFAULT 0,
			error_code varchar(100) NOT NULL DEFAULT '',
			reverts_entry_id bigint(20) unsigned NOT NULL DEFAULT 0,
			reverted_by_entry_id bigint(20) unsigned NOT NULL DEFAULT 0,
			revision bigint(20) unsigned NOT NULL DEFAULT 1,
			payload longtext NOT NULL,
			PRIMARY KEY  (id),
			KEY created_at (created_at),
			KEY tool_created (tool,created_at),
			KEY user_created (user_id,created_at),
			KEY status_created (status,created_at),
			KEY target_created (target,created_at)
		) $collation;" );
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table ) {
			update_option( 'kodanote_mcp_audit_schema', self::SCHEMA, false );
		}
	}

	public static function maybe_install(): void {
		if ( self::SCHEMA !== get_option( 'kodanote_mcp_audit_schema' ) ) { self::install(); }
	}

	public static function cleanup(): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table() . ' WHERE created_at < %s', gmdate( 'Y-m-d H:i:s', time() - self::RETENTION_DAYS * DAY_IN_SECONDS ) ) );
	}

	public static function definitions(): array {
		$id = array( 'type' => 'integer', 'minimum' => 1 );
		return array(
			self::definition( 'list_audit_log', 'List MCP mutation history', 'Filter MCP mutation history retained for 90 days. Returns metadata only, newest first. Requires manage_options and audit:read. Native WordPress or other-plugin edits are not logged here.', array(
				'page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100000, 'default' => 1 ),
				'per_page' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 50, 'default' => 20 ),
				'tool' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 64 ),
				'user_id' => $id,
				'status' => array( 'type' => 'string', 'enum' => array( 'pending', 'success', 'failed', 'partial', 'reverting', 'reverted' ) ),
				'target' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 191, 'description' => 'Exact target identifier from an audit entry.' ),
				'after' => array( 'type' => 'string', 'format' => 'date-time', 'description' => 'Inclusive creation time lower bound in RFC 3339 format.' ),
				'before' => array( 'type' => 'string', 'format' => 'date-time', 'description' => 'Inclusive creation time upper bound in RFC 3339 format.' ),
			), array(), true ),
			self::definition( 'get_audit_entry', 'Inspect an MCP mutation', 'Read metadata, safe before/after state and a version for an audited mutation. Requires manage_options and audit:read. Content snapshots may contain private site content; OAuth tokens and raw request arguments are never stored.', array( 'id' => $id ), array( 'id' ), true ),
			self::definition( 'revert_audit_entry', 'Revert an audited mutation', 'Restore an eligible successful mutation only while its recorded after-state still matches the site. Requires audit:write, the original write scope, and all current WordPress permissions. Supply the version from get_audit_entry. Reverts are audited and cannot themselves be reverted. Created objects are never deleted automatically; failed, partial, expired and already reverted entries cannot be reverted.', array(
				'id' => $id, 'version' => array( 'type' => 'string', 'pattern' => '^[a-f0-9]{64}$' ),
			), array( 'id', 'version' ), false ),
		);
	}

	public static function required_scope( string $name ): ?string {
		return in_array( $name, array( 'list_audit_log', 'get_audit_entry' ), true ) ? 'audit:read' : ( 'revert_audit_entry' === $name ? 'audit:write' : null );
	}

	public static function can_use( string $name ): bool {
		return null !== self::required_scope( $name ) && get_current_user_id() && current_user_can( 'read' ) && current_user_can( 'manage_options' );
	}

	public static function call( string $name, array $input ) {
		if ( ! self::can_use( $name ) ) { return self::error( 'forbidden', 'You may not inspect or revert MCP mutation history.', 403 ); }
		foreach ( self::definitions() as $definition ) {
			if ( $name === $definition['name'] ) {
				$valid = rest_validate_value_from_schema( $input, $definition['inputSchema'], 'arguments' );
				if ( is_wp_error( $valid ) ) { return $valid; }
				break;
			}
		}
		if ( 'list_audit_log' === $name ) { return self::listing( $input ); }
		if ( 'get_audit_entry' === $name ) {
			$row = self::row( $input['id'] );
			return $row ? self::details( $row ) : self::error( 'not_found', 'This audit entry does not exist or has expired.', 404 );
		}
		return self::revert( $input );
	}

	/** Called once at the authenticated transport boundary, after input and scope checks. */
	public static function execute( string $name, array $input, array $grant ) {
		$old_grant = self::$grant;
		$old_entry = self::$active_entry;
		self::$grant = $grant;
		try {
			$mutation = false;
			foreach ( Tools::definitions() as $definition ) {
				if ( $definition['name'] === $name ) { $mutation = empty( $definition['annotations']['readOnlyHint'] ); break; }
			}
			if ( ! $mutation ) { return Tools::call( $name, $input ); }
			return self::record_mutation( $name, $input, $grant );
		} finally {
			self::$grant = $old_grant;
			self::$active_entry = $old_entry;
		}
	}

	private static function record_mutation( string $name, array $input, array $grant ) {
		global $wpdb;
		$context = self::context( $name, $input );
		$before = self::snapshot( $context );
		$payload = array( 'context' => $context, 'before' => is_wp_error( $before ) ? null : $before, 'after' => null,
			'revert_reason' => $context['reason'] );
		$encoded = self::encode( $payload );
		if ( is_wp_error( $encoded ) ) { return $encoded; }
		$now = gmdate( 'Y-m-d H:i:s' );
		$inserted = $wpdb->insert( self::table(), array(
			'created_at' => $now, 'updated_at' => $now, 'user_id' => get_current_user_id(),
			'client_id' => substr( sanitize_text_field( $grant['client_id'] ?? '' ), 0, 128 ),
			'tool' => $name, 'target' => $context['target'], 'status' => 'pending',
			'reverts_entry_id' => 'revert_audit_entry' === $name ? (int) $input['id'] : 0, 'payload' => $encoded,
		) );
		if ( false === $inserted || (int) $wpdb->insert_id < 1 ) { return self::error( 'audit_unavailable', 'The mutation was not performed because its audit entry could not be saved.', 503 ); }
		$id = (int) $wpdb->insert_id;
		self::$active_entry = $id;
		if ( is_wp_error( $before ) ) {
			self::finish( $id, 'failed', $payload, false, $before->get_error_code() );
			return self::with_error_id( $before, $id );
		}
		try {
			$result = Tools::call( $name, $input );
		} catch ( \Throwable $exception ) {
			$result = self::error( 'mutation_failed', 'The mutation failed unexpectedly. Inspect its audit entry and current site state before retrying.', 500 );
		}
		if ( ! is_wp_error( $result ) && ! empty( $context['created'] ) && isset( $result['id'] ) ) {
			$context = self::created_context( $context, $result );
			$payload['context'] = $context;
		}
		$after = self::snapshot( $context );
		$payload['after'] = is_wp_error( $after ) ? null : $after;
		$changed = ! is_wp_error( $after ) && self::fingerprint( $before ) !== self::fingerprint( $after );
		$success = ! is_wp_error( $result );
		$status = $success ? 'success' : ( $changed || is_wp_error( $after ) || ! empty( $context['created'] ) ? 'partial' : 'failed' );
		$reversible = $success && ! is_wp_error( $after ) && ! empty( $context['adapter'] ) && empty( $context['created'] ) && 'revert_audit_entry' !== $name;
		if ( is_wp_error( $after ) ) {
			$status = 'partial';
			$payload['revert_reason'] = 'The after-state could not be captured. Inspect the site manually before retrying.';
		} elseif ( ! $success ) {
			$payload['revert_reason'] = ! empty( $context['created'] ) ? 'Creation failed without a verified outcome; a new object may exist. Inspect WordPress before retrying.' : ( $changed ? 'The operation failed after changing site state; manual review is required.' : 'Failed operations cannot be reverted.' );
		} elseif ( $reversible ) {
			$reason = self::restore_limitation( $context, $before );
			if ( $reason ) { $reversible = false; $payload['revert_reason'] = $reason; }
		}
		$error_code = is_wp_error( $result ) ? $result->get_error_code() : ( is_wp_error( $after ) ? $after->get_error_code() : '' );
		if ( is_wp_error( self::encode( $payload ) ) ) {
			// Hooks may enlarge the saved object unexpectedly. Keep a bounded final record
			// instead of leaving a completed mutation looking like an unstarted request.
			$payload['after'] = null;
			$payload['revert_reason'] = 'The resulting state exceeded the audit snapshot limit. Inspect the site manually; automatic revert is unavailable.';
			if ( is_wp_error( self::encode( $payload ) ) ) { $payload['before'] = null; }
			$status = 'partial'; $reversible = false; $error_code = 'audit_snapshot_too_large';
			$result = self::error( 'audit_incomplete', 'The mutation may have completed, but the resulting audit snapshot exceeded its size limit. Inspect the site before retrying.', 500 );
		}
		if ( ! self::finish( $id, $status, $payload, $reversible, $error_code, $context['target'] ) ) {
			return self::error( 'audit_incomplete', 'The mutation may have completed, but its final audit record could not be saved. Inspect audit entry ' . $id . ' and the site before retrying.', 500 );
		}
		if ( is_wp_error( $result ) ) { return self::with_error_id( $result, $id ); }
		if ( is_wp_error( $after ) ) { return self::with_error_id( self::error( 'audit_incomplete', 'The mutation completed but its after-state is unavailable. Inspect the site before retrying.', 500 ), $id ); }
		$result['audit'] = array( 'id' => $id, 'status' => $status, 'reversible' => $reversible );
		return $result;
	}

	/** Store field names and object identifiers, never raw request arguments or OAuth credentials. */
	private static function context( string $name, array $input ): array {
		$context = array( 'tool' => $name, 'scope' => Tools::required_scope( $name ), 'adapter' => '', 'args' => array(), 'fields' => array(),
			'target' => $name, 'reason' => 'This operation has no safe automatic revert adapter.', 'created' => false );
		$adapters = array( 'update_site_settings' => 'settings', 'update_global_styles' => 'global_styles',
			'update_template' => 'template', 'update_layout' => 'template', 'update_navigation' => 'navigation',
			'update_media' => 'media', 'update_content' => 'content', 'trash_content' => 'trash' );
		$created = array( 'create_content' => 'content', 'create_template' => 'template', 'create_navigation' => 'navigation', 'create_term' => 'term' );
		$context['adapter'] = $adapters[ $name ] ?? ( $created[ $name ] ?? '' );
		$context['created'] = isset( $created[ $name ] );
		if ( $context['adapter'] ) { $context['reason'] = ''; }
		if ( $context['created'] ) { $context['reason'] = 'Creation is recorded, but automatic revert would delete a new object. Review it in WordPress instead.'; }
		if ( isset( $input['id'] ) ) { $context['args']['id'] = $input['id']; }
		if ( 'template' === $context['adapter'] ) { $context['args']['type'] = $input['type'] ?? 'template'; }
		if ( 'term' === $context['adapter'] ) { $context['args']['taxonomy'] = $input['taxonomy'] ?? 'category'; }
		if ( 'settings' === $context['adapter'] ) { $context['fields'] = array_keys( $input['settings'] ); }
		elseif ( 'update_layout' === $name ) { $context['fields'] = array( 'content' ); }
		elseif ( 'trash' === $context['adapter'] ) { $context['fields'] = array( 'status', 'slug', 'comment_statuses' ); }
		else { $context['fields'] = array_values( array_diff( array_keys( $input ), array( 'id', 'type', 'version', 'post_type' ) ) ); }
		$context['target'] = self::target( $context );
		if ( 'revert_audit_entry' === $name ) { $context['target'] = 'audit:' . $input['id']; $context['reason'] = 'A revert cannot itself be reverted automatically.'; }
		return $context;
	}

	private static function target( array $context ): string {
		$adapter = $context['adapter'];
		if ( 'settings' === $adapter ) { return 'site:settings'; }
		if ( 'global_styles' === $adapter ) { return substr( 'theme:' . get_stylesheet() . ':global-styles', 0, 191 ); }
		$id = $context['args']['id'] ?? 'new';
		if ( 'template' === $adapter ) { return substr( 'template:' . $context['args']['type'] . ':' . $id, 0, 191 ); }
		if ( 'term' === $adapter ) { return 'term:' . $context['args']['taxonomy'] . ':' . $id; }
		return ( 'trash' === $adapter ? 'content' : ( $adapter ?: $context['tool'] ) ) . ':' . $id;
	}

	private static function created_context( array $context, array $result ): array {
		$context['args']['id'] = $result['id'];
		$context['target'] = self::target( $context );
		return $context;
	}

	private static function snapshot( array $context ) {
		try { return self::snapshot_unchecked( $context ); }
		catch ( \Throwable $exception ) { return self::error( 'snapshot_failed', 'The current site state could not be captured safely.', 500 ); }
	}

	private static function snapshot_unchecked( array $context ) {
		if ( 'revert_audit_entry' === $context['tool'] ) {
			$row = self::row( (int) $context['args']['id'] );
			if ( ! $row ) { return array( 'entry_id' => (int) $context['args']['id'], 'available' => false ); }
			$payload = json_decode( $row['payload'], true );
			// Revert entries cannot themselves be undone; avoid following audit chains recursively.
			if ( 'revert_audit_entry' === ( $payload['context']['tool'] ?? '' ) ) { return array( 'entry_id' => (int) $row['id'], 'status' => $row['status'] ); }
			$state = self::snapshot( $payload['context'] );
			return array( 'entry_id' => (int) $row['id'], 'status' => $row['status'], 'target' => $row['target'],
				'state' => is_wp_error( $state ) ? null : $state, 'state_available' => ! is_wp_error( $state ) );
		}
		if ( ! $context['adapter'] || ( ! empty( $context['created'] ) && ! isset( $context['args']['id'] ) ) ) { return null; }
		$adapter = $context['adapter'];
		if ( 'global_styles' === $adapter ) {
			if ( ! Tools::can_use( 'get_global_styles' ) ) { return self::error( 'forbidden', 'You may not inspect the current global styles.', 403 ); }
			$record = \WP_Theme_JSON_Resolver::get_user_data_from_wp_global_styles( wp_get_theme(), false );
			$config = isset( $record['post_content'] ) ? json_decode( $record['post_content'], true ) : array();
			if ( ! is_array( $config ) ) { return self::error( 'invalid_snapshot', 'The current global style data cannot be captured safely.', 409 ); }
			return array( 'theme' => get_stylesheet(), 'settings' => $config['settings'] ?? array(), 'styles' => $config['styles'] ?? array() );
		}
		if ( 'term' === $adapter ) {
			$term = get_term( $context['args']['id'], $context['args']['taxonomy'] );
			if ( ! $term || is_wp_error( $term ) ) { return self::error( 'not_found', 'The created term cannot be inspected.', 404 ); }
			return array( 'id' => (int) $term->term_id, 'taxonomy' => $term->taxonomy, 'name' => $term->name, 'slug' => $term->slug, 'description' => $term->description, 'parent' => (int) $term->parent );
		}
		$tools = array( 'settings' => 'get_site_settings', 'template' => 'get_template', 'navigation' => 'get_navigation', 'media' => 'get_media', 'content' => 'get_content', 'trash' => 'get_content' );
		$data = Tools::call( $tools[ $adapter ], $context['args'] );
		if ( is_wp_error( $data ) ) { return $data; }
		$state = self::project_snapshot( $adapter, $data );
		if ( 'trash' === $adapter ) {
			// Native untrash restores comment statuses too, including comments moderated
			// while the post was trashed. Include only IDs/statuses so such drift blocks undo.
			global $wpdb;
			$comments = $wpdb->get_results( $wpdb->prepare( 'SELECT comment_ID, comment_approved FROM ' . $wpdb->comments . ' WHERE comment_post_ID=%d ORDER BY comment_ID ASC LIMIT 1001', $context['args']['id'] ), ARRAY_A );
			if ( null === $comments || $wpdb->last_error ) { return self::error( 'snapshot_failed', 'Comment statuses could not be captured safely.', 503 ); }
			if ( count( $comments ) > 1000 ) { return self::error( 'audit_too_large', 'Audited trash operations support at most 1,000 comments per item.', 413 ); }
			$state['comment_statuses'] = array_map( static function ( $comment ) { return array( 'id' => (int) $comment['comment_ID'], 'status' => (string) $comment['comment_approved'] ); }, $comments );
			$map = get_post_meta( $context['args']['id'], '_wp_trash_meta_comments_status', true );
			if ( '' === $map || false === $map ) { $map = array(); }
			if ( ! is_array( $map ) || count( $map ) > 1000 ) { return self::error( 'invalid_snapshot', 'The saved comment restoration map is invalid or exceeds the audit limit.', 409 ); }
			$state['trash_comment_statuses'] = array();
			foreach ( $map as $comment_id => $status ) {
				if ( ! ctype_digit( (string) $comment_id ) || (int) $comment_id < 1 || ! is_scalar( $status ) || strlen( (string) $status ) > 32 ) { return self::error( 'invalid_snapshot', 'The saved comment restoration map is invalid.', 409 ); }
				$state['trash_comment_statuses'][ (int) $comment_id ] = (string) $status;
			}
		}
		return $state;
	}

	private static function project_snapshot( string $adapter, array $data ): array {
		if ( 'settings' === $adapter ) { return $data['settings']; }
		$keys = array(
			'template' => array( 'id', 'theme', 'type', 'title', 'description', 'content', 'area', 'status' ),
			'navigation' => array( 'id', 'title', 'status', 'content' ),
			'media' => array( 'id', 'title', 'caption', 'description', 'alt_text', 'parent' ),
			'content' => array( 'id', 'type', 'status', 'title', 'content', 'excerpt', 'slug', 'date', 'categories', 'tags', 'featured_media_id', 'seo' ),
		);
		$state = array_intersect_key( $data, array_flip( $keys[ 'trash' === $adapter ? 'content' : $adapter ] ) );
		if ( 'template' === $adapter ) { $state['active_theme'] = get_stylesheet(); }
		return $state;
	}

	private static function restore_limitation( array $context, $before ): string {
		if ( 'trash' === $context['adapter'] && ( ! is_array( $before ) || ! in_array( $before['status'] ?? '', array( 'draft', 'pending', 'publish', 'future', 'private' ), true ) ) ) {
			return 'Only a post or page moved from an ordinary status into trash can be restored.';
		}
		if ( 'global_styles' === $context['adapter'] ) { return ''; }
		if ( 'trash' === $context['adapter'] ) { return ''; }
		$args = self::restore_arguments( $context, $before, str_repeat( '0', 64 ) );
		$name = self::restore_tool( $context );
		foreach ( Tools::definitions() as $definition ) {
			if ( $name === $definition['name'] ) {
				return is_wp_error( rest_validate_value_from_schema( $args, $definition['inputSchema'], 'restore' ) ) ? 'The previous values are outside the current safe write schema; restore them manually in WordPress.' : '';
			}
		}
		return 'No supported restoration tool is available.';
	}

	private static function revert( array $input ) {
		global $wpdb;
		if ( ! self::$active_entry || ! in_array( 'audit:write', explode( ' ', self::$grant['scope'] ?? '' ), true ) ) {
			return self::error( 'forbidden', 'Reverting requires an authenticated, audited MCP request with audit:write.', 403 );
		}
		$row = self::row( $input['id'] );
		if ( ! $row ) { return self::error( 'not_found', 'This audit entry does not exist or has expired.', 404 ); }
		if ( ! hash_equals( self::entry_version( $row ), $input['version'] ) ) { return self::error( 'conflict', 'The audit entry changed. Read it again before reverting.', 409 ); }
		if ( 'success' !== $row['status'] || ! $row['reversible'] || ! empty( $row['reverted_by_entry_id'] ) ) {
			return self::error( 'not_reversible', 'This entry is not eligible for automatic revert.', 409 );
		}
		$payload = json_decode( $row['payload'], true );
		$context = $payload['context'];
		$scope = $context['scope'];
		if ( ! in_array( $scope, explode( ' ', self::$grant['scope'] ?? '' ), true ) || ! Tools::can_use( $context['tool'] ) || ! Tools::can_use( self::restore_tool( $context ) ) ) {
			return self::error( 'forbidden', 'Reverting requires the original write scope and current permissions for the original operation and its restoration.', 403 );
		}
		$claimed = $wpdb->query( $wpdb->prepare( 'UPDATE ' . self::table() . " SET status='reverting', revision=revision+1, updated_at=%s WHERE id=%d AND revision=%d AND status='success' AND reversible=1 AND reverted_by_entry_id=0", gmdate( 'Y-m-d H:i:s' ), $row['id'], $row['revision'] ) );
		if ( 1 !== $claimed ) { return self::error( 'conflict', 'Another request changed or is reverting this audit entry.', 409 ); }
		$current = self::snapshot( $context );
		if ( is_wp_error( $current ) || self::fingerprint( $current ) !== self::fingerprint( $payload['after'] ) ) {
			self::release_claim( $row['id'] );
			return is_wp_error( $current ) ? $current : self::error( 'drift', 'The current site state differs from this entry’s recorded after-state. Revert is blocked to preserve later edits.', 409 );
		}
		try { $result = self::restore( $context, $payload['before'], $payload['after'] ); }
		catch ( \Throwable $error ) { $result = self::error( 'revert_failed', 'Restoration failed unexpectedly. Inspect the site and audit log before retrying.', 500 ); }
		$restored = self::snapshot( $context );
		if ( is_wp_error( $result ) || is_wp_error( $restored ) || ! self::restored_fields_match( $context, $payload['before'], $restored ) ) {
			if ( ! is_wp_error( $restored ) && self::fingerprint( $restored ) === self::fingerprint( $payload['after'] ) ) {
				self::release_claim( $row['id'] );
			} else {
				$payload['revert_reason'] = 'A restoration failed or was sanitized differently. Manual review is required before any further restoration.';
				self::finish( $row['id'], 'partial', $payload, false, 'revert_incomplete' );
			}
			return is_wp_error( $result ) ? $result : self::error( 'revert_incomplete', 'The restored state could not be verified exactly. Inspect the site and audit log before retrying.', 500 );
		}
		$payload['revert_reason'] = 'This entry has already been reverted.';
		if ( ! self::finish( $row['id'], 'reverted', $payload, false, '', null, self::$active_entry ) ) {
			return self::error( 'audit_incomplete', 'Restoration completed, but its original audit entry could not be finalized. Inspect both audit records before retrying.', 500 );
		}
		return array( 'reverted_entry_id' => (int) $row['id'], 'result' => $result );
	}

	private static function release_claim( int $id ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . self::table() . " SET status='success', revision=revision+1, updated_at=%s WHERE id=%d AND status='reverting'", gmdate( 'Y-m-d H:i:s' ), $id ) );
	}

	private static function restore_tool( array $context ): string {
		$names = array( 'settings' => 'update_site_settings', 'global_styles' => 'update_global_styles', 'template' => 'update_template', 'navigation' => 'update_navigation', 'media' => 'update_media', 'content' => 'update_content', 'trash' => 'update_content' );
		return $names[ $context['adapter'] ] ?? '';
	}

	private static function restore_arguments( array $context, array $before, string $version ): array {
		$fields = array_intersect_key( $before, array_flip( $context['fields'] ) );
		if ( 'settings' === $context['adapter'] ) { return array( 'version' => $version, 'settings' => $fields ); }
		$args = array_merge( $context['args'], $fields );
		if ( ! in_array( $context['adapter'], array( 'content', 'trash' ), true ) ) { $args['version'] = $version; }
		return $args;
	}

	private static function restore( array $context, array $before, array $expected_after ) {
		$adapter = $context['adapter'];
		if ( 'global_styles' === $adapter ) {
			if ( get_stylesheet() !== $before['theme'] || ! current_user_can( 'edit_theme_options' ) || ! wp_theme_has_theme_json() ) { return self::error( 'forbidden', 'The active theme or its current permissions prevent restoring these styles.', 403 ); }
			$record = \WP_Theme_JSON_Resolver::get_user_data_from_wp_global_styles( wp_get_theme(), false );
			$id = (int) ( $record['ID'] ?? 0 );
			if ( ! $id || ! current_user_can( 'edit_post', $id ) ) { return self::error( 'forbidden', 'The global styles record is no longer editable.', 403 ); }
			$config = json_decode( $record['post_content'], true );
			$current = array( 'theme' => get_stylesheet(), 'settings' => $config['settings'] ?? array(), 'styles' => $config['styles'] ?? array() );
			if ( self::fingerprint( $current ) !== self::fingerprint( $expected_after ) ) { return self::error( 'drift', 'Global styles changed during restoration preparation. No restore was performed.', 409 ); }
			$request = new \WP_REST_Request( 'POST', '/wp/v2/global-styles/' . $id );
			$request->set_body_params( array( 'context' => 'edit', 'settings' => $before['settings'], 'styles' => $before['styles'] ) );
			$response = rest_do_request( $request );
			if ( is_wp_error( $response ) ) { return $response; }
			if ( $response->is_error() ) { return $response->as_error(); }
			\WP_Theme_JSON_Resolver::clean_cached_data();
			wp_clean_theme_json_cache();
			return Tools::call( 'get_global_styles', array() );
		}
		if ( 'trash' === $adapter ) {
			$id = (int) $context['args']['id'];
			$post = get_post( $id );
			$type = $post ? get_post_type_object( $post->post_type ) : null;
			if ( ! $post || ! $type || 'trash' !== $post->post_status || ! current_user_can( 'delete_post', $id ) || ! current_user_can( 'edit_post', $id ) || ! current_user_can( 'read_post', $id ) || ( in_array( $before['status'], array( 'publish', 'private', 'future' ), true ) && ! current_user_can( $type->cap->publish_posts ) ) ) {
				return self::error( 'forbidden', 'You may not restore this trashed item to its previous status.', 403 );
			}
			if ( 'future' === $before['status'] && strtotime( get_gmt_from_date( $before['date'] ) . ' UTC' ) <= time() ) { return self::error( 'invalid_date', 'The original scheduled date has passed. Restore and reschedule the item manually.', 409 ); }
			if ( $before['slug'] && wp_unique_post_slug( $before['slug'], $id, $before['status'], $post->post_type, $post->post_parent ) !== $before['slug'] ) {
				return self::error( 'drift', 'The original URL slug is now occupied. Restore this item manually to choose its URL.', 409 );
			}
			$current = self::snapshot( $context );
			if ( is_wp_error( $current ) || self::fingerprint( $current ) !== self::fingerprint( $expected_after ) ) { return self::error( 'drift', 'The trashed item changed during restoration preparation. No restore was performed.', 409 ); }
			$restore_status = static function ( $status, $post_id ) use ( $id, $before ) { return $post_id === $id ? $before['status'] : $status; };
			add_filter( 'wp_untrash_post_status', $restore_status, PHP_INT_MAX, 2 );
			try { $restored = wp_untrash_post( $id ); }
			finally { remove_filter( 'wp_untrash_post_status', $restore_status, PHP_INT_MAX ); }
			if ( ! $restored ) { return self::error( 'revert_failed', 'WordPress could not restore the trashed item.', 500 ); }
			// Core restores only truthy _wp_desired_post_slug values. A draft with an
			// originally empty slug would otherwise keep the generated __trashed slug.
			if ( '' === $before['slug'] && '' !== get_post_field( 'post_name', $id, 'raw' ) ) {
				$result = Tools::call( 'update_content', array( 'id' => $id, 'slug' => '' ) );
				if ( is_wp_error( $result ) ) { return $result; }
				delete_post_meta( $id, '_wp_desired_post_slug', '' );
				return $result;
			}
			return Tools::call( 'get_content', array( 'id' => $id ) );
		}
		$reads = array( 'settings' => 'get_site_settings', 'template' => 'get_template', 'navigation' => 'get_navigation', 'media' => 'get_media', 'content' => 'get_content' );
		$current = Tools::call( $reads[ $adapter ], $context['args'] );
		if ( is_wp_error( $current ) ) { return $current; }
		// Bind the fresh version to the state that was checked, rather than blessing a concurrent edit.
		if ( self::fingerprint( self::project_snapshot( $adapter, $current ) ) !== self::fingerprint( $expected_after ) ) {
			return self::error( 'drift', 'The object changed during restoration preparation. No restore was performed.', 409 );
		}
		return Tools::call( self::restore_tool( $context ), self::restore_arguments( $context, $before, $current['version'] ?? '' ) );
	}

	private static function restored_fields_match( array $context, array $before, $after ): bool {
		if ( ! is_array( $after ) ) { return false; }
		if ( 'global_styles' === $context['adapter'] ) { return self::fingerprint( $before ) === self::fingerprint( $after ); }
		$keys = array_flip( $context['fields'] );
		return self::fingerprint( array_intersect_key( $before, $keys ) ) === self::fingerprint( array_intersect_key( $after, $keys ) );
	}

	private static function finish( int $id, string $status, array $payload, bool $reversible, string $error_code = '', ?string $target = null, int $reverted_by = 0 ): bool {
		global $wpdb;
		$encoded = self::encode( $payload );
		if ( is_wp_error( $encoded ) ) { return false; }
		$changes = array( 'status' => $status, 'reversible' => (int) $reversible, 'payload' => $encoded, 'updated_at' => gmdate( 'Y-m-d H:i:s' ), 'error_code' => substr( preg_replace( '/[^a-zA-Z0-9_-]/', '', $error_code ), 0, 100 ) );
		if ( null !== $target ) { $changes['target'] = $target; }
		if ( $reverted_by ) { $changes['reverted_by_entry_id'] = $reverted_by; }
		$updated = $wpdb->update( self::table(), $changes, array( 'id' => $id ) );
		if ( false === $updated ) { return false; }
		return 1 === $wpdb->query( $wpdb->prepare( 'UPDATE ' . self::table() . ' SET revision=revision+1 WHERE id=%d', $id ) );
	}

	private static function listing( array $input ) {
		global $wpdb;
		$where = array( 'created_at >= %s' );
		$values = array( gmdate( 'Y-m-d H:i:s', time() - self::RETENTION_DAYS * DAY_IN_SECONDS ) );
		foreach ( array( 'tool', 'user_id', 'status', 'target' ) as $key ) {
			if ( isset( $input[ $key ] ) ) { $where[] = $key . ( 'user_id' === $key ? ' = %d' : ' = %s' ); $values[] = $input[ $key ]; }
		}
		foreach ( array( 'after' => '>=', 'before' => '<=' ) as $key => $operator ) {
			if ( isset( $input[ $key ] ) ) {
				$timestamp = strtotime( $input[ $key ] );
				if ( false === $timestamp ) { return self::error( 'invalid_date', 'Use a valid RFC 3339 audit filter date.', 400 ); }
				$where[] = 'created_at ' . $operator . ' %s'; $values[] = gmdate( 'Y-m-d H:i:s', $timestamp );
			}
		}
		$page = $input['page'] ?? 1; $per_page = $input['per_page'] ?? 20;
		$values[] = $per_page + 1; $values[] = ( $page - 1 ) * $per_page;
		$columns = 'id,created_at,updated_at,user_id,client_id,tool,target,status,reversible,error_code,reverts_entry_id,reverted_by_entry_id,revision';
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT ' . $columns . ' FROM ' . self::table() . ' WHERE ' . implode( ' AND ', $where ) . ' ORDER BY id DESC LIMIT %d OFFSET %d', $values ), ARRAY_A );
		if ( null === $rows || $wpdb->last_error ) { return self::error( 'audit_unavailable', 'Audit history is currently unavailable.', 503 ); }
		return array( 'items' => array_map( array( self::class, 'summary' ), array_slice( $rows, 0, $per_page ) ), 'page' => $page, 'has_more' => count( $rows ) > $per_page );
	}

	private static function row( int $id ): ?array {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . self::table() . ' WHERE id=%d AND created_at >= %s', $id, gmdate( 'Y-m-d H:i:s', time() - self::RETENTION_DAYS * DAY_IN_SECONDS ) ), ARRAY_A ) ?: null;
	}

	private static function summary( array $row ): array {
		$result = array_intersect_key( $row, array_flip( array( 'id', 'created_at', 'updated_at', 'user_id', 'client_id', 'tool', 'target', 'status', 'reversible', 'error_code', 'reverts_entry_id', 'reverted_by_entry_id' ) ) );
		foreach ( array( 'id', 'user_id', 'reverts_entry_id', 'reverted_by_entry_id' ) as $key ) { $result[ $key ] = (int) $result[ $key ]; }
		$result['reversible'] = (bool) $result['reversible'] && 'success' === $row['status'];
		foreach ( array( 'created_at', 'updated_at' ) as $key ) { $result[ $key ] = str_replace( ' ', 'T', $result[ $key ] ) . 'Z'; }
		return $result;
	}

	private static function details( array $row ): array {
		$payload = json_decode( $row['payload'], true );
		return self::summary( $row ) + array(
			'version' => self::entry_version( $row ), 'before' => $payload['before'] ?? null, 'after' => $payload['after'] ?? null,
			'changed_fields' => $payload['context']['fields'] ?? array(), 'required_write_scope' => $payload['context']['scope'] ?? null,
			'revert_reason' => $payload['revert_reason'] ?? '',
		);
	}

	private static function entry_version( array $row ): string {
		return self::fingerprint( array( $row['id'], $row['revision'], $row['status'], $row['payload'], $row['reverted_by_entry_id'] ) );
	}

	private static function fingerprint( $value ): string {
		$sort = static function ( $item ) use ( &$sort ) {
			if ( ! is_array( $item ) ) { return $item; }
			if ( ! array_is_list( $item ) ) { ksort( $item ); }
			return array_map( $sort, $item );
		};
		return hash( 'sha256', wp_json_encode( $sort( $value ) ) );
	}

	private static function encode( array $payload ) {
		$json = wp_json_encode( $payload );
		return ! is_string( $json ) || strlen( $json ) > self::MAX_PAYLOAD ? self::error( 'audit_too_large', 'The safe audit snapshot exceeds the 2 MiB limit. This operation cannot be audited safely.', 413 ) : $json;
	}

	private static function with_error_id( \WP_Error $error, int $id ): \WP_Error {
		$data = $error->get_error_data();
		$error->add_data( array_merge( is_array( $data ) ? $data : array(), array( 'audit_entry_id' => $id ) ) );
		return $error;
	}

	private static function error( string $code, string $message, int $status ): \WP_Error {
		return new \WP_Error( 'kodanote_mcp_' . $code, $message, array( 'status' => $status ) );
	}

	private static function definition( string $name, string $title, string $description, array $properties, array $required, bool $read ): array {
		return array( 'name' => $name, 'title' => $title, 'description' => $description,
			'inputSchema' => array( 'type' => 'object', 'properties' => $properties, 'required' => $required, 'additionalProperties' => false ),
			'annotations' => array( 'readOnlyHint' => $read, 'destructiveHint' => ! $read, 'idempotentHint' => $read, 'openWorldHint' => false ),
		);
	}
}
