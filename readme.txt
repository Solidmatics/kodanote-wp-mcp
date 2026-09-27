=== Kodanote MCP ===
Contributors: kodanote
Tags: mcp, oauth, ai, content
Requires at least: 6.5
Requires PHP: 8.1
Stable tag: 0.3.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Role-aware WordPress tools for remote MCP clients, with OAuth, WordPress login and consent, and per-user permissions.

== Description ==

Connect an OAuth-capable remote MCP client to your WordPress site. The plugin serves a stateless Streamable HTTP endpoint and its own OAuth authorization server; no external auth service or Composer dependencies are required.

Supports posts/pages, categories/tags, featured images, Yoast SEO, theme colors and typography, Global Styles Additional CSS, block templates, headers/footers, block navigation menus, targeted layouts, widths and spacing, homepage/blog/permalink settings, reading/discussion/media settings, media metadata, user/plugin inventories, and MCP audit history with supported undo. Tool discovery and every operation check the user's current WordPress capabilities and delegated OAuth scopes. Custom roles work through capabilities. Consent allows selecting individual permissions or read-only access.

The plugin uses authorization codes with S256 PKCE, dynamic client registration, resource-bound access tokens, rotating refresh tokens and connection revocation. HTTPS is required. No WordPress Application Password is needed for this endpoint.

== Installation ==

1. Upload the plugin ZIP through Plugins > Add New > Upload Plugin, or copy kodanote-mcp into wp-content/plugins.
2. Activate it on an individual WordPress site.
3. Enable pretty permalinks and HTTPS. Ensure /.well-known/ OAuth discovery requests reach WordPress.
4. Open Users > MCP Connections (or Profile > MCP Connections) and copy the MCP URL.
5. Add that URL as a remote custom connector in your MCP client, connect, sign in to WordPress and approve access.

See README.md for exact endpoints, server configuration, local development, supported tools and limitations.

== Frequently Asked Questions ==

= Does it need the Kodanote Content Publisher or WordPress MCP Adapter? =
No. It operates independently. Existing publishing hooks still run when managed content is edited.

= Can I revoke access? =
Yes. Users > MCP Connections lists your connections and offers immediate revocation. Authorizations also expire after 30 days.

= Does it support old SSE-only clients or stdio? =
No. Use a client supporting Streamable HTTP and OAuth discovery/registration, or pre-register its OAuth credentials using the registration endpoint.

= Can it install plugins, run PHP or permanently delete content? =
No. It exposes only the documented content, appearance and administration tools. Plugin/user management currently provides inventories; role changes, installation, arbitrary PHP, and permanent deletion are not exposed.

== Changelog ==

= 0.3.2 =
Add versioned Global Styles Additional CSS replacement and reset through custom_css, with a 50,000-character limit, native WordPress validation and edit_css permission checks. Preserve unrelated appearance settings and expose CSS writability on reads. Prevent style updates and audit reversals from silently stripping saved CSS when the caller lacks CSS permission.
Reject updates and reversals before saving when native permission filtering would discard unrelated settings or styles. Preserve explicit empty-palette resets by removing the user palette override.

= 0.3.1 =
Fix browser Content Security Policy blocking the return to an MCP client after OAuth approval or cancellation. Keep consent submissions on the current origin and preserve nonce, session and exact callback validation.

= 0.3.0 =
Header/footer discovery and creation, reusable block navigation menus, targeted nested layout edits preserving theme pattern references, and global widths/gaps/padding. Expands routine site settings to homepage/blog selection, safe permalink presets, feeds, discussion, avatars and image sizes. Adds filterable MCP mutation history and guarded undo with separate audit scopes. 31 capability-gated tools; classic PHP themes and page builders need separate integrations.

= 0.2.0 =
Role-aware discovery, granular OAuth consent, theme palette/styles and templates, site settings, media metadata, user/plugin inventories, and stale-version protection for appearance/settings/media writes. Reconnect existing OAuth connections to grant additional scopes.

= 0.1.0 =
Initial standalone MCP and OAuth implementation.
