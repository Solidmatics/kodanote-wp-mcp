<?php
namespace Kodanote\MCP;

defined( 'ABSPATH' ) || exit;

final class Admin {
	public static function boot(): void {
		add_action( 'admin_menu', static function () {
			add_users_page( 'MCP Connections', 'MCP Connections', 'read', 'kodanote-mcp', array( self::class, 'page' ) );
			add_management_page( 'MCP Audit Log', 'MCP Audit Log', 'manage_options', 'kodanote-mcp-audit', array( self::class, 'audit_page' ) );
		} );
		add_action( 'admin_post_kodanote_mcp_revoke', array( self::class, 'revoke' ) );
	}

	/** Human-readable inspection uses WordPress login; MCP access additionally requires audit scopes. */
	public static function audit_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		$id = isset( $_GET['entry'] ) ? absint( $_GET['entry'] ) : 0;
		?><div class="wrap"><h1>MCP Audit Log</h1><p>MCP changes are retained for 90 days. This history covers changes made through this plugin; it is not a full site backup or a log of all WordPress activity. Use the audit MCP tools to inspect and undo supported changes.</p><?php
		if ( $id ) {
			$entry = Audit::call( 'get_audit_entry', array( 'id' => $id ) );
			if ( is_wp_error( $entry ) ) { echo '<p>' . esc_html( $entry->get_error_message() ) . '</p>'; }
			else {
				echo '<h2>Entry ' . esc_html( (string) $id ) . '</h2><pre style="white-space:pre-wrap;overflow-wrap:anywhere;background:#fff;padding:16px">' . esc_html( wp_json_encode( $entry, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ) . '</pre>';
			}
			echo '<p><a href="' . esc_url( admin_url( 'tools.php?page=kodanote-mcp-audit' ) ) . '">Back to audit history</a></p></div>';
			return;
		}
		$args = array( 'page' => min( 100000, max( 1, absint( $_GET['paged'] ?? 1 ) ) ), 'per_page' => 20 );
		foreach ( array( 'tool', 'target', 'status' ) as $key ) {
			if ( isset( $_GET[ $key ] ) && is_string( $_GET[ $key ] ) && '' !== $_GET[ $key ] ) { $args[ $key ] = sanitize_text_field( wp_unslash( $_GET[ $key ] ) ); }
		}
		if ( ! empty( $_GET['user_id'] ) ) { $args['user_id'] = absint( $_GET['user_id'] ); }
		?><form method="get"><input type="hidden" name="page" value="kodanote-mcp-audit">
		<label>Tool <input name="tool" value="<?php echo esc_attr( $args['tool'] ?? '' ); ?>"></label>
		<label>Target <input name="target" value="<?php echo esc_attr( $args['target'] ?? '' ); ?>"></label>
		<label>User ID <input type="number" min="1" name="user_id" value="<?php echo esc_attr( (string) ( $args['user_id'] ?? '' ) ); ?>" style="width:90px"></label>
		<label>Status <select name="status"><option value="">All</option><?php foreach ( array( 'pending', 'success', 'failed', 'partial', 'reverting', 'reverted' ) as $status ) : ?><option value="<?php echo esc_attr( $status ); ?>" <?php selected( $args['status'] ?? '', $status ); ?>><?php echo esc_html( $status ); ?></option><?php endforeach; ?></select></label>
		<button class="button" type="submit">Filter</button></form><p></p><?php
		$result = Audit::call( 'list_audit_log', $args );
		if ( is_wp_error( $result ) ) { echo '<p>' . esc_html( $result->get_error_message() ) . '</p></div>'; return; }
		?><table class="widefat striped"><thead><tr><th>Entry</th><th>Time (UTC)</th><th>User</th><th>Tool</th><th>Target</th><th>Status</th><th>Undo supported</th></tr></thead><tbody><?php
		foreach ( $result['items'] as $entry ) {
			$url = add_query_arg( array( 'page' => 'kodanote-mcp-audit', 'entry' => $entry['id'] ), admin_url( 'tools.php' ) );
			echo '<tr><td><a href="' . esc_url( $url ) . '">' . esc_html( (string) $entry['id'] ) . '</a></td>';
			foreach ( array( 'created_at', 'user_id', 'tool', 'target', 'status' ) as $key ) { echo '<td>' . esc_html( (string) $entry[ $key ] ) . '</td>'; }
			echo '<td>' . ( $entry['reversible'] ? 'Yes, if unchanged' : 'No' ) . '</td></tr>';
		}
		if ( ! $result['items'] ) { echo '<tr><td colspan="7">No matching MCP changes.</td></tr>'; }
		echo '</tbody></table><p>';
		foreach ( array( 'Previous' => $args['page'] - 1, 'Next' => $args['page'] + 1 ) as $label => $page ) {
			if ( $page < 1 || ( 'Next' === $label && empty( $result['has_more'] ) ) ) { continue; }
			$query = $args;
			unset( $query['per_page'] );
			$query['page'] = 'kodanote-mcp-audit'; $query['paged'] = $page;
			echo '<a class="button" href="' . esc_url( add_query_arg( $query, admin_url( 'tools.php' ) ) ) . '">' . esc_html( $label ) . '</a> ';
		}
		echo '</p></div>';
	}

	public static function revoke(): void {
		if ( ! current_user_can( 'read' ) ) { wp_die( 'Permission denied.', '', array( 'response' => 403 ) ); }
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) { wp_die( 'Use POST.', '', array( 'response' => 405 ) ); }
		check_admin_referer( 'kodanote_mcp_revoke' );
		$id = isset( $_POST['grant_id'] ) && is_string( $_POST['grant_id'] ) ? wp_unslash( $_POST['grant_id'] ) : '';
		$grant = Store::get( 'grant', $id );
		if ( $grant && (int) $grant['user_id'] === get_current_user_id() ) { Store::revoke_grant( $id ); }
		wp_safe_redirect( self_admin_url( ( current_user_can( 'edit_users' ) ? 'users.php' : 'profile.php' ) . '?page=kodanote-mcp' ) ); exit;
	}

	public static function page(): void {
		if ( ! current_user_can( 'read' ) ) { return; }
		$grants = Store::grants_for_user( get_current_user_id() );
		?><div class="wrap"><h1>Kodanote MCP</h1>
		<p>Connect Claude or another remote MCP client with this URL. Sign in to WordPress and choose the access to grant. Tools are available only when both the connection and your current WordPress capabilities allow them.</p>
		<p><code><?php echo esc_html( Plugin::resource_url() ); ?></code></p>
		<?php if ( ! Plugin::secure() ) : ?><div class="notice notice-error inline"><p>OAuth is disabled until the site uses HTTPS.</p></div><?php endif; ?>
		<?php if ( ! get_option( 'permalink_structure' ) ) : ?><div class="notice notice-warning inline"><p>Enable pretty permalinks in Settings → Permalinks for broad MCP client compatibility and OAuth discovery.</p></div><?php endif; ?>
		<p><a href="<?php echo esc_url( Plugin::resource_metadata_url() ); ?>" target="_blank" rel="noopener">Resource metadata</a> · <a href="<?php echo esc_url( Plugin::oauth_url( 'metadata' ) ); ?>" target="_blank" rel="noopener">Authorization server metadata</a></p>
		<p>Clients may register themselves automatically. In Claude, add a custom connector using the MCP URL, then connect. Reconnect an existing content-only connection to grant access to appearance, media or administration tools.</p>
		<h2>Permissions available to your account</h2><ul><?php foreach ( Access::available_scopes() as $scope ) : $definition = Access::scopes()[ $scope ]; ?><li><strong><?php echo esc_html( $definition['label'] ); ?></strong>: <?php echo esc_html( $definition['description'] ); ?></li><?php endforeach; ?></ul>
		<h2>Your connections</h2><p>Revoking a connection immediately invalidates its access and refresh tokens. Reconnect after the 30-day authorization expires.</p>
		<table class="widefat striped"><thead><tr><th>Application</th><th>Access</th><th>Authorized</th><th>Expires</th><th>Action</th></tr></thead><tbody>
		<?php foreach ( $grants as $grant ) : ?><tr><td><?php echo esc_html( $grant['client_name'] ); ?></td><td><?php echo esc_html( $grant['scope'] ); ?></td><td><?php echo esc_html( wp_date( 'Y-m-d H:i', $grant['created'] ) ); ?></td><td><?php echo esc_html( wp_date( 'Y-m-d H:i', $grant['expires'] ) ); ?></td><td><form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="kodanote_mcp_revoke"><input type="hidden" name="grant_id" value="<?php echo esc_attr( $grant['id'] ); ?>"><?php wp_nonce_field( 'kodanote_mcp_revoke' ); ?><button class="button" name="revoke" type="submit">Revoke</button></form></td></tr><?php endforeach; ?>
		<?php if ( ! $grants ) : ?><tr><td colspan="5">No active connections.</td></tr><?php endif; ?></tbody></table></div><?php
	}
}
