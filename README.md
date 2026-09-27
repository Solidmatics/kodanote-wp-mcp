# Kodanote MCP for WordPress

A standalone WordPress plugin that gives remote MCP clients role-aware content, appearance and administration tools through WordPress login and OAuth consent. No separate Node server, external identity provider, Composer install, WordPress MCP Adapter, or Content Publisher dependency is needed.

## Install and connect

1. Build with `python3 scripts/package.py`, then upload `dist/kodanote-mcp-0.3.2.zip` in **Plugins → Add New → Upload Plugin**. Alternatively copy this directory to `wp-content/plugins/kodanote-mcp` and activate it. On the existing Kodanote deployment, vendor it into the WordPress repository before deploying because production disallows file modifications.
2. Use HTTPS and pretty permalinks. Activate per site; network-wide activation is deliberately rejected.
3. Open **Users → MCP Connections**, or **Profile → MCP Connections** for users who cannot manage users, and copy the displayed endpoint:

   ```text
   https://your-site.example/wp-json/kodanote-mcp/v1/mcp
   ```

4. In Claude, add a custom remote connector with that URL, then connect. A compatible client discovers OAuth and registers itself automatically; leave manual client credentials empty for dynamic registration. Sign in to WordPress, review the callback destination, select individual permissions, and approve the selection or its read-only subset.
5. Ask the client to list content, inspect theme colors, or use the other tools your account permits. An Editor can work on site-wide content and media and read theme styling. Theme/template changes and site administration need the corresponding WordPress administrative capabilities. Authors and Contributors keep their normal content restrictions.

**Upgrading from 0.1.0:** reconnect to request the new appearance, media and administration scopes. Existing content-only tokens and refresh tokens keep their original permissions. Version 0.1.0 client registrations also retain their content-only scope ceiling: if the client caches its registration, remove and re-add the connector so it registers again and presents fresh consent. A new registration includes all supported scopes by default.

**Upgrading from 0.2.0:** header, footer, navigation and layout tools use the existing appearance scopes; broader site settings use the existing settings scopes. Audit history and undo require new `audit:read` / `audit:write` consent. Older client registrations retain their original scope ceiling, so remove/re-add the connector to register again if it cannot request the audit scopes. Existing tokens never gain new scopes automatically.

Revoke a connection from **MCP Connections** at any time. Access tokens last one hour. Refresh tokens rotate on every use, with an absolute 30-day authorization lifetime; reconnect after that. Changing the WordPress password also invalidates existing authorizations. Reusing a redeemed code or refresh token revokes its authorization family.

Claude's hosted connector needs a publicly reachable HTTPS site; it cannot reach the test server on your laptop. The automated suite exercises the full flow against real local WordPress. A live Claude account connection still needs to be verified after deployment; no claim of universal client certification is made.

## Role-aware access

The accessible toolset is the intersection of **the OAuth scopes approved by the user** and **the user's current WordPress capabilities**. Unavailable tools are hidden from `tools/list`; calling one directly still fails. Capability checks run on every request, so revoking a role capability takes effect for existing tokens. Custom roles work without adding role names to the plugin.

| Standard role | Typical access when the matching scopes are approved |
| --- | --- |
| Contributor | Own drafts/pending posts, permitted term reads, theme colors and typography reads |
| Author | Own content and media, publishing, theme colors and typography reads |
| Editor | Site content, taxonomy and media work, theme colors and typography reads |
| Administrator | The above plus global appearance edits, block templates, headers/footers, navigation, layouts, selected site settings, user/plugin inventories, MCP audit history and supported undo |

Subscribers have no MCP access with default capabilities. A custom design role with `read` and `edit_theme_options` can access global appearance tools without content or user management permissions; template controllers in newer WordPress versions additionally require permission to edit a REST-exposed post type. A taxonomy-only role can authorize content scopes to use its permitted term tools. Multisite and capability filters can further restrict what core WordPress REST controllers allow. `get_site_info` belongs to `content:read`; connections delegated only other families discover their available operations through `tools/list`.

There are 31 tools across seven scope families. `content`, `appearance`, `media`, `settings` and `audit` have separate `:read` and `:write` scopes; `plugins` and `users` currently have only `:read`. A write scope includes its own family's read scope. Consent displays only permissions the account can grant, with individual checkboxes. WordPress roles do not automatically turn all REST endpoints into MCP tools.

## Content tools

| Tool | Scope | Purpose |
| --- | --- | --- |
| `get_site_info` | `content:read` | Site identity and the current user's content permissions |
| `list_content` | `content:read` | Paginated posts/pages the user may read and edit |
| `get_content` | `content:read` | One post/page, including raw block markup |
| `create_content` | `content:write` | Create a post/page; defaults to draft |
| `update_content` | `content:write` | Change only the supplied fields |
| `trash_content` | `content:write` | Move content to trash; refuses permanent deletion |
| `list_terms` | `content:read` | List categories or tags |
| `create_term` | `content:write` | Create a category or tag when permitted |

Write authorizations also include read access. OAuth scopes never bypass WordPress capabilities. Publishing, scheduling, private content, and modifications to already published content require publish permission. Author-restricted listing and item permission checks prevent disclosure of other users' drafts/private content.

Content inputs include title, HTML/block content, excerpt, slug, status, publication date, existing category/tag IDs and `featured_media_id`. Optional `seo` fields are `title`, `description`, and `focus_keyphrase`; they require active Yoast SEO.

Example tool call:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "create_content",
    "arguments": { "title": "New article", "content": "<!-- wp:paragraph --><p>A draft.</p><!-- /wp:paragraph -->" }
  }
}
```

## Appearance tools

| Tool | Scope | Required WordPress capability |
| --- | --- | --- |
| `get_theme` | `appearance:read` | `edit_posts`, `edit_pages`, or `edit_theme_options` |
| `get_global_styles` | `appearance:read` | `edit_posts`, `edit_pages`, or `edit_theme_options` |
| `update_global_styles` | `appearance:write` | `edit_theme_options`; also `edit_css` when supplying or preserving custom CSS |
| `list_templates` / `get_template` | `appearance:read` | `edit_theme_options` |
| `create_template` / `update_template` | `appearance:write` | `edit_theme_options` |
| `get_layout` | `appearance:read` | `edit_theme_options` |
| `update_layout` | `appearance:write` | `edit_theme_options` |
| `list_navigation` / `get_navigation` | `appearance:read` | `edit_theme_options`, plus native menu permissions |
| `create_navigation` / `update_navigation` | `appearance:write` | `edit_theme_options`, plus native menu create/edit/publish permissions |

`get_theme` identifies the active child/parent theme and supported features. `get_global_styles` reads merged WordPress defaults, inherited theme settings, and saved user overrides, including palette and typography presets. This covers the sibling Kodanote child theme's inherited Twenty Twenty-Five colors rather than inspecting only its almost-empty child `theme.json`.

`update_global_styles` accepts the `version` from the last read and any of:

- `palette`: replacement user palette containing `{slug, name, color}` entries; colors are hex values. Existing theme/default palettes remain inherited. Include existing user entries you want to retain; an empty array removes user palette entries.
- `background_color`, `text_color`, `link_color`: hex values or existing `var:preset|color|slug` references; `null` removes that override.
- `font_family_slug`, `font_size_slug`: existing typography preset slugs; `null` removes that override.
- `content_width`, `wide_width`, `block_gap`: nonnegative CSS lengths such as `720px`, `80rem`, or `0`; `null` removes that override.
- `padding`: an object with supplied `top`, `right`, `bottom`, and/or `left` lengths. Unspecified sides are preserved; a `null` side removes that side's override, and `padding: null` removes all user padding overrides. Supported units are `px`, `rem`, `em`, `%`, `vw`, and `vh`. Expressions such as `calc()` are not accepted as new values.
- `custom_css`: the complete replacement for the user's Global Styles Additional CSS, up to 50,000 characters. Omit it to preserve current CSS, use `""` to save an empty value, or `null` to remove the user override. This changes the `styles.css` text stored in WordPress's database; it does not edit a theme stylesheet file.

Other user settings and styles are preserved. Global style edits require a theme with `theme.json`. Classic-theme reads also report standard editor palettes and standard background/header color customizations, but arbitrary stylesheet rules, theme-specific Customizer options and page-builder data need dedicated integrations.

For CSS changes, first read `get_global_styles` and retain the complete `user.styles.css` value (absent means no user override). Edit only the intended rules, then submit the replacement with the returned `version`. The read response's `writable` flag describes general appearance access; `css_writable` also requires native `edit_css` permission. Both flags describe WordPress capabilities and theme support, not the connection's OAuth write scopes. A connection still needs `appearance:write` to save.

CSS uses the same native validation and save filters as the Site Editor, including rejection of unsafe STYLE-element closing markup. This is not a CSS syntax linter: selectors, media queries, expressions and quoted content accepted by WordPress remain intact. Invalid input is checked before creating a missing user Global Styles record. A CSS update or reset requires `edit_css`; so does any other global-style update when existing root or nested custom CSS would otherwise be stripped by WordPress's permission filtering. In that case the tool fails without changing the configuration. Existing audit snapshots include CSS, and undo applies the same permission and drift safeguards before restoring it.

For callers without `unfiltered_html`, updates and undo also check the complete proposed configuration against native Global Styles filtering before saving. If WordPress would discard settings or styles, the operation fails without modifying the record. Ordinary edits remain available when that filtering preserves the configuration.

After deploying a plugin update, refresh the client's MCP tool discovery to see the new `custom_css` argument. Existing appearance scopes remain sufficient; no additional OAuth scope is introduced.

Template tools accept `type: "template"` or `"template_part"` and exact IDs returned by `list_templates`. Filter parts by `area: "header"` or `"footer"`, or find templates by `search`. `update_template` requires `id` and `version`, and accepts title, description or complete replacement block markup; parts also accept an `area`. It creates/updates database overrides through the Site Editor controller, never writes PHP/theme files, and requires block-template support. These edits and global style edits affect the live site. Width and spacing effects depend on the theme and individual blocks' layout support.

`create_template` takes a missing `slug`, `title`, and complete block `content`, with optional `type`, `description`, and part `area`. It rejects existing slugs, including inherited theme templates. New parts must be inserted into a template to appear. A new template whose slug matches the WordPress template hierarchy can immediately affect matching pages; other custom templates need assignment through WordPress. This version does not provide an assignment tool.

## Headers, footers, navigation, and layouts

For block themes, headers and footers are editable template parts. This includes the Twenty Twenty-Five parent used by the neighboring Kodanote theme. An agent can follow this workflow:

1. Call `list_templates` with `{ "type": "template_part", "area": "footer" }` (or `"header"`) and choose the exact returned ID.
2. Call `get_layout` with that ID and `type: "template_part"`. It returns the saved block tree, the complete markup of each block, its `path`, and the current `version`. Template-part and navigation references are visible in block attributes; read those referenced parts/menus separately to edit their contents.
3. Call `update_layout` with that ID, type, version and an `operations` array. Each operation supplies `action` (`replace`, `insert_before`, `insert_after`, or `remove`) and a returned block `path`. Insert/replace also takes complete block `content`; remove must omit it. This supports rearranging groups, columns, navigation, text and other saved blocks while preserving surrounding markup.
4. Re-read after saving or a version conflict. Operations run in order, so later paths refer to the tree after earlier edits. Paths include whitespace/freeform nodes: use returned paths rather than counting visible blocks.

Theme pattern references stay intact in `content` and `blocks`. `resolved_content` and `resolved_blocks` separately show expanded patterns for inspection; resolved blocks have no editable paths. To customize a pattern-based footer, deliberately replace its raw pattern reference with the expanded markup you want to change. Editing elsewhere leaves that pattern reference in place.

For example, replace the block at a path returned by `get_layout`:

```json
{
  "id": "your-theme//footer",
  "type": "template_part",
  "version": "<version from get_layout>",
  "operations": [{
    "action": "replace",
    "path": [0, 1],
    "content": "<!-- wp:paragraph --><p>Our updated footer.</p><!-- /wp:paragraph -->"
  }]
}
```

The example ID, version and path must be replaced with actual read results. All operations are validated in memory before one template save. Invalid paths, malformed block delimiters, invalid attribute JSON, PHP, and stale versions fail without saving that batch. The tool accepts up to 50 operations, 1,000 parsed blocks, 16 nesting levels, and 500,000 bytes of markup. Supply both attributes and saved HTML when changing a static block; server parsing does not replace Gutenberg's browser-side block validation. To add children to an empty container, replace that container with complete markup. Use `update_template` for a whole-template replacement. Page/post body layouts remain editable through `get_content` and `update_content`.

`list_navigation`, `get_navigation`, `create_navigation`, and `update_navigation` manage reusable block navigation menus, including nested submenus. Read before updating and supply the returned `version`. Menu content is the **inner** navigation block markup, without an outer `core/navigation` wrapper. Native links, submenus, page lists, home links, search, social links, spacers, site title/logo, login/out and buttons are supported, up to 250 blocks, 8 nesting levels and 150,000 characters. Arbitrary HTML/shortcode blocks and reusable block references inside menus are rejected.

New menus default to `draft`. Explicitly publish with `update_navigation` before inserting the returned `navigation_block` snippet into a header/footer using `update_layout`. The snippet contains `<!-- wp:navigation {"ref":123} /-->` with the actual menu ID. Targeted layout edits reject references to missing, inaccessible or unpublished menus. Editing a published menu changes every place that references it. Publishing a menu can also affect WordPress's automatic fallback in navigation blocks that have no selected menu. Existing inline navigation can be edited as part of the containing layout instead.

## Administration and media tools

| Tool | Scope | Required WordPress capability |
| --- | --- | --- |
| `get_site_settings` | `settings:read` | `manage_options` |
| `update_site_settings` | `settings:write` | `manage_options` |
| `list_plugins` | `plugins:read` | `activate_plugins` |
| `list_users` | `users:read` | `list_users` |
| `list_media` / `get_media` | `media:read` | `upload_files`, plus attachment read/edit permissions |
| `update_media` | `media:write` | `upload_files`, plus attachment read/edit permissions |

Site settings use an explicit allowlist of 35 controls. An update takes `{version, settings: {…}}` using the preceding read's version, and preserves omitted settings:

| Area | Writable settings |
| --- | --- |
| General / writing | `title`, `description`, `timezone`, `date_format`, `time_format`, `start_of_week`, `default_category`, `default_post_format`, `use_smilies` |
| Homepage / reading | `show_on_front`, `page_on_front`, `page_for_posts`, `posts_per_page`, `posts_per_rss`, `rss_use_excerpt` |
| Permalinks | `permalink_structure` using the documented pretty presets |
| Discussion | `default_comment_status`, `close_comments_for_old_posts`, `close_comments_days_old`, `thread_comments`, `thread_comments_depth`, `page_comments`, `comments_per_page`, `default_comments_page`, `comment_order` |
| Avatars | `show_avatars`, `avatar_rating`, `avatar_default` |
| New image sizes | `thumbnail_size_w`, `thumbnail_size_h`, `thumbnail_crop`, `medium_size_w`, `medium_size_h`, `large_size_w`, `large_size_h` |

Set `show_on_front: "page"` with a published, password-free `page_on_front` ID. `page_for_posts` must be a different published, password-free page; `0` leaves no separate blog page. Both pages must be readable/editable by the user. Use `show_on_front: "posts"` for latest posts. Relationships are checked before writing any supplied setting.

Permalink choices are `/%postname%/`, `/%year%/%monthnum%/%day%/%postname%/`, `/%year%/%monthnum%/%postname%/`, `/archives/%post_id%` (also accepted with a trailing slash), and `/%category%/%postname%/`. These change public post URLs and can affect existing links and SEO; automatic redirect migration is not provided. Existing pretty-permalink server routing is required. Plain, `index.php`, and arbitrary custom permalink transitions are excluded to preserve the exact OAuth MCP resource URL. Rewrite rules are refreshed in the database without writing server configuration files.

Discussion defaults affect new posts unless the setting explicitly controls global comment display. Image size changes affect future uploads; existing images are not regenerated. User registration, default roles, passwords, admin email, site URLs, search-engine visibility and arbitrary plugin options are excluded.

Plugin inventory contains identifiers, names, versions and activation status. User inventory contains IDs, display names, public slugs and roles. Neither exposes credentials or private user email addresses. Media reads return accessible existing attachments; updates take `id`, `version` and supplied `title`, `caption`, `description`, `alt_text` or `parent` fields. Parent content must also be readable/editable by the connected user.

Appearance, template, layout, navigation, settings and media updates reject a stale `version` before writing. These are optimistic read-before-write checks; they do not lock WordPress against simultaneous external edits or turn multi-option settings writes into database transactions. Read again and review current values after a conflict.

## Audit history and undo

MCP mutation history is available in **Tools → MCP Audit Log** in WordPress and through three MCP tools:

| Tool | Scope | Purpose |
| --- | --- | --- |
| `list_audit_log` | `audit:read` | Filter metadata by exact tool, target, user ID, status, and RFC 3339 `after` / `before` times; paginate with `page` / `per_page` (maximum 50) |
| `get_audit_entry` | `audit:read` | Inspect actor/client IDs, timestamps, outcome, changed field names, before/after snapshots, undo eligibility, and entry version |
| `revert_audit_entry` | `audit:write` | Supply `{id, version}` from the preceding read to restore an eligible edit |

Both scopes require `manage_options`. Undo additionally requires the original operation's write scope, its current WordPress capabilities, and current permission to edit the affected object. Giving an agent audit access alone does not let it change settings, content or appearance. Audit read consent explicitly includes private content snapshots; it is not granted to ordinary Editors or Authors by default.

Every mutation that reaches tool execution first saves a pending audit entry. If that entry cannot be saved, the mutation is blocked. Successful tool results include `audit: {id, status, reversible}`. The log records successful and failed attempts, and reports partial/uncertain outcomes when changes may have happened before a failure. Authentication, scope, capability or schema failures rejected before tool execution are not recorded. Ordinary reads are not logged.

Supported undo covers settings, global styles, templates, targeted layouts, navigation, media metadata, content updates and moving content to trash. It restores the previous values through permission-checked WordPress operations, and records the undo itself with a link to the original entry. Trash operations also track comment IDs/statuses (up to 1,000 comments per item), so restoring a post cannot silently overwrite an intervening moderation change. New posts, menus, templates and terms are recorded but not automatically deleted by undo. Each entry reports whether undo is supported and, if not, why; failed, partial, expired, already reverted and undo entries are ineligible. Restoring prior values outside the current safe schema or a scheduled publication whose date has passed may require manual editing in WordPress.

Before restoring, the plugin compares the current safe resource snapshot with the recorded after-state. Any difference blocks undo, including a later change from WordPress admin or another plugin. This is intentionally conservative: an unrelated change within that same snapshot also blocks undo. A per-entry database claim prevents two requests from reverting the same entry together. The original write and undo still use optimistic checks, not a database transaction spanning all WordPress hooks; they cannot lock out simultaneous external edits or undo emails, webhooks, publisher synchronization effects, or other plugin side effects.

History is retained for 90 days in this site's `kodanote_mcp_audit` table. Individual snapshots are bounded by a 2 MiB serialized entry limit; list results omit snapshot bodies. OAuth tokens, passwords, authorization codes, raw request arguments, IP addresses and arbitrary options are not added to the log. Content snapshots can still contain whatever sensitive information is present in the edited content itself. Only this plugin's MCP mutations are tracked: this is not a site-wide activity log, an immutable security ledger, or a replacement for site/database backups. Site administrators with direct database access can alter it. Deactivation retains history; uninstall removes it.

## Remaining boundaries

- Content tools cover standard posts/pages and categories/tags, not arbitrary custom post types, WooCommerce, or third-party plugin APIs.
- No generic REST proxy, arbitrary options/meta access, PHP/shell execution, or filesystem/theme-source edits is exposed. Add a dedicated tool and capability/scope policy for further integrations.
- User/plugin tools are inventories: no account/role changes, plugin installation/activation, theme switching, or WordPress updates.
- Media tools manage existing metadata; there is no upload, URL sideload, binary replacement or file deletion tool.
- Global appearance writes cover the documented colors, typography presets, widths, gaps, padding and the user's Global Styles Additional CSS. Block templates/parts and block navigation are supported. Theme stylesheet files, classic PHP header/footer files, classic menu locations, Customizer panels, widgets and page-builder internals require dedicated integrations.
- Content deletion remains trash-only; existing per-item and publish capability checks still apply.

## OAuth and transport

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/wp-json/kodanote-mcp/v1/mcp` | POST | Authenticated JSON-RPC MCP |
| `/.well-known/oauth-authorization-server` | GET | Authorization server discovery |
| `/.well-known/oauth-protected-resource` | GET | Protected resource discovery |
| `/wp-json/kodanote-mcp/v1/oauth/metadata` | GET | Authorization metadata alias |
| `/wp-json/kodanote-mcp/v1/oauth/resource-metadata` | GET | Metadata URL advertised in `WWW-Authenticate` |
| `/wp-json/kodanote-mcp/v1/oauth/register` | POST JSON | Dynamic client registration |
| `/wp-admin/admin-post.php?action=kodanote_mcp_authorize` | GET/POST | Login and explicit consent |
| `/wp-json/kodanote-mcp/v1/oauth/token` | POST form | Code exchange / refresh |
| `/wp-json/kodanote-mcp/v1/oauth/revoke` | POST form | Revoke a token's entire authorization |

Uses OAuth authorization codes, mandatory S256 PKCE, exact registered redirect matching, and RFC 8707 resource binding. Send the exact MCP URL as `resource` in authorization and code exchange requests. Refresh accepts an omitted resource or the same resource, never a different audience. Only `authorization_code` and `refresh_token` grants are supported. DCR supports public clients (explicit `token_endpoint_auth_method: "none"`) and confidential clients (`client_secret_post`, `client_secret_basic`). Per RFC 7591, an omitted authentication method defaults to `client_secret_basic` and omitted grant types default to `authorization_code` only; request `refresh_token` explicitly for refresh support. Confidential client secrets are returned once. HTTPS redirect URIs are accepted; HTTP is accepted only for loopback callbacks. Registered callbacks are exact matches, including their ports. Client names are unverified and shown as such on consent.

Client ID Metadata Documents (URL-valued client IDs) are not implemented or advertised. Clients should use dynamic registration or pre-register through the same registration endpoint and supply the returned credentials. Clients requiring only CIMD, legacy HTTP+SSE, stdio, or a different authentication scheme are outside this version's support.

MCP protocol versions `2025-11-25`, `2025-06-18`, and `2025-03-26` are negotiated. The transport is stateless Streamable HTTP with JSON responses, no session ID and no server-initiated SSE. Send `Content-Type: application/json`, `Accept: application/json, text/event-stream`, and `Authorization: Bearer …` on every request. Unauthenticated requests return 401 with OAuth metadata discovery; authenticated GET/DELETE requests return 405, as permitted for this transport. Initialized/cancelled notifications receive an empty 202 response. Batches are not supported.

Public registration is limited to 20 requests per IP per hour and 1,000 per site per day. Token/revocation requests are each limited to 300 per IP per hour. Consent pages are limited to 100 per IP per hour. Limits use database counters and `REMOTE_ADDR`; configure trusted proxies at the web server so one shared proxy does not become every client's address. Client registrations expire after one year; re-register if needed. Expired records are cleaned hourly by WP-Cron.

## Hosting configuration

- Forward the `Authorization` header to PHP. The sibling Kodanote site's Apache configuration already does this.
- Route `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` through WordPress instead of blocking them as dotfiles. Path-qualified discovery URLs are also handled. These endpoints must return JSON directly, not a theme HTML page or a login redirect.
- WordPress in a subdirectory needs its domain-root well-known requests routed to its front controller. The issuer path is included in RFC 8414 discovery, e.g. `/.well-known/oauth-authorization-server/blog` for `https://example.com/blog`.
- Exclude the MCP/OAuth endpoints and consent responses from CDN/page caching. Responses include `Cache-Control: no-store`.
- Consent submits to the current origin. Its completion page uses a nonce-protected navigation script and a Continue link to return to the client, keeping `form-action 'self'` without blocking external OAuth callbacks.
- HTTPS must be configured in WordPress and recognized by `is_ssl()` on the request. If TLS terminates at a reverse proxy, configure HTTPS recognition only from that trusted proxy; this plugin does not blindly trust forwarded headers.
- Requests without an Origin header (typical server clients) are supported. Browser Origins must match the site or the built-in `https://claude.ai` origin. Add other trusted browser origins explicitly:

  ```php
  add_filter( 'kodanote_mcp_allowed_origins', function ( $origins ) {
      $origins[] = 'https://your-mcp-client.example';
      return $origins;
  } );
  ```

  CORS grants no cookie credentials. MCP still requires its own Bearer token. OAuth endpoints expose public-client CORS and enforce their own client/PKCE validation.

For local development only, set both `WP_ENVIRONMENT_TYPE` to `local` or `development` and `KODANOTE_MCP_ALLOW_HTTP` to `true` in `wp-config.php`. This explicit exception is ignored in production.

## Existing Kodanote integrations

The Content Publisher uses shared-key/HMAC endpoints under `/kodanote/v1`; this plugin keeps OAuth credentials separate. It edits standard WordPress posts/pages through core controllers and does not overwrite publisher synchronization metadata. Publisher hooks still execute: modifying a synced article's body may mark it as manually managed, preventing later automatic body updates.

The existing WordPress MCP Adapter endpoint and `kodanote-abilities.php` remain independent. This plugin uses a different endpoint and does not load or expose the site's ability registry. OAuth tokens issued here do not authorize the old Basic-auth MCP endpoint or the general WordPress REST API.

## Development and verification

```bash
find . -name '*.php' -not -path './dist/*' -exec php -l {} \;
php tests/transport.php
bash tests/run-integration.sh
python3 scripts/package.py
```

The integration harness requires PHP with mysqli, Python 3, Docker with `mysql:8.4`, and a WordPress source checkout (defaults to `../kodanote-web-wp`). It copies only WordPress core into a temporary directory, uses a disposable database container and test accounts, runs real HTTP OAuth/MCP tests, then removes the temporary environment. It never loads the neighboring site's configuration, plugins, credentials, or database. See the script for environment overrides.

The suite checks discovery, granular login/consent and CSRF/session binding, PKCE, client/redirect/resource binding, code/refresh replay, token revocation, WordPress Application Password coexistence, scope enforcement, role-filtered discovery, content/media permissions, theme/user palette merging, layout sizes/padding, header/footer overrides without theme-file changes, pattern preservation, navigation persistence, targeted nested layout edits and invalid-batch rejection, routine settings/permalink behavior, audit filtering and privacy, mutation/undo records, restoration across supported resources, drift and replay rejection, audit storage failure, and stale-version rejection. The transport suite checks protocol negotiation, malformed JSON, schema validation, authentication challenges, capability-gated dispatch and Origin/CORS rules.

Plugin-owned OAuth records live in the site's `kodanote_mcp` table with the configured WP table prefix. Bearer/code/refresh secrets and confidential client secrets are stored only as SHA-256 hashes. Deactivation retains records; uninstall removes this site's OAuth/audit tables, audit schema marker, and cleanup schedule, without touching content.

Standards used: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [protected resource metadata](https://www.rfc-editor.org/rfc/rfc9728), and [OAuth authorization server metadata](https://www.rfc-editor.org/rfc/rfc8414).
