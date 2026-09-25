#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
core_source="${WP_CORE_SOURCE:-$(dirname "$repo_root")/kodanote-web-wp}"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/kodanote-mcp-test.XXXXXX")"
database_container="kodanote-mcp-test-$(basename "$test_root" | tr '[:upper:]' '[:lower:]')"
server_pid=""
database_port="${KODANOTE_MCP_TEST_DB_PORT:-33079}"
http_port="${KODANOTE_MCP_TEST_HTTP_PORT:-18089}"

cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    docker rm --force "$database_container" >/dev/null 2>&1 || true
    if [[ "${KODANOTE_MCP_KEEP_TEST_FILES:-0}" == 1 ]]; then
        printf 'Test files retained at %s\n' "$test_root"
    else
        rm -rf "$test_root"
    fi
}
trap cleanup EXIT

if [[ ! -f "$core_source/wp-includes/version.php" ]]; then
    printf 'Set WP_CORE_SOURCE to a WordPress core checkout. Only core files will be copied.\n' >&2
    exit 1
fi
mkdir -p "$test_root/wordpress/wp-content/plugins" "$test_root/wordpress/wp-content/mu-plugins" "$test_root/wordpress/wp-content/themes/mcp-test/templates" "$test_root/wordpress/wp-content/themes/mcp-test/parts"
printf '/* Theme Name: Integration Test Fixture */\n' > "$test_root/wordpress/wp-content/themes/mcp-test/style.css"
printf '<?php // Empty integration test theme.\n' > "$test_root/wordpress/wp-content/themes/mcp-test/index.php"
cat > "$test_root/wordpress/wp-content/themes/mcp-test/theme.json" <<'JSON'
{
    "version": 3,
    "settings": {
        "layout": {"contentSize": "680px", "wideSize": "1200px"},
        "color": {
            "palette": [
                {"slug": "primary", "name": "Primary", "color": "#112233"},
                {"slug": "secondary", "name": "Secondary", "color": "#445566"}
            ]
        },
        "typography": {
            "fontFamilies": [{"slug": "fixture-serif", "name": "Fixture serif", "fontFamily": "Georgia, serif"}],
            "fontSizes": [{"slug": "fixture-small", "name": "Fixture small", "size": "14px"}]
        }
    },
    "styles": {"color": {"text": "var:preset|color|primary"}},
    "templateParts": [
        {"name": "header", "title": "Fixture header", "area": "header"},
        {"name": "footer", "title": "Fixture footer", "area": "footer"}
    ]
}
JSON
cat > "$test_root/wordpress/wp-content/themes/mcp-test/templates/index.html" <<'HTML'
<!-- wp:template-part {"slug":"header","theme":"mcp-test","tagName":"header"} /-->
<!-- wp:paragraph --><p>Template fixture</p><!-- /wp:paragraph -->
<!-- wp:template-part {"slug":"footer","theme":"mcp-test","tagName":"footer"} /-->
HTML
cat > "$test_root/wordpress/wp-content/themes/mcp-test/parts/header.html" <<'HTML'
<!-- wp:group {"layout":{"type":"constrained"}} --><div class="wp-block-group"><!-- wp:site-title /--><!-- wp:navigation {"ref":0} /--></div><!-- /wp:group -->
HTML
cat > "$test_root/wordpress/wp-content/themes/mcp-test/parts/footer.html" <<'HTML'
<!-- wp:group {"tagName":"footer","className":"fixture-footer","layout":{"type":"constrained"}} -->
<footer class="wp-block-group fixture-footer"><!-- wp:paragraph -->
<p>Footer fixture <strong>bold unchanged</strong></p>
<!-- /wp:paragraph -->
<!-- wp:group {"className":"fixture-nested","layout":{"type":"flex","justifyContent":"space-between"}} -->
<div class="wp-block-group fixture-nested"><!-- wp:paragraph -->
<p>Nested footer link area</p>
<!-- /wp:paragraph --></div>
<!-- /wp:group --></footer>
<!-- /wp:group -->
<!-- wp:pattern {"slug":"mcp-test/preserved-footer"} /-->
HTML
cat > "$test_root/wordpress/wp-content/mu-plugins/integration-fixture.php" <<'PHP'
<?php
// The isolated test site never sends email or checks wordpress.org for updates.
add_filter('pre_wp_mail', '__return_true');
remove_action('admin_init', '_maybe_update_core');
remove_action('admin_init', '_maybe_update_plugins');
remove_action('admin_init', '_maybe_update_themes');
add_action('init', static function () {
    register_block_pattern('mcp-test/preserved-footer', array(
        'title' => 'Preserved footer fixture',
        'content' => '<!-- wp:paragraph --><p>Resolved footer pattern fixture</p><!-- /wp:paragraph -->',
    ));
    // Fault injection is confined to this disposable test installation.
    if ('audit_insert' === get_option('kodanote_mcp_test_fault')) {
        global $wpdb;
        $table = $wpdb->prefix . 'kodanote_mcp_audit';
        add_filter('query', static function ($query) use ($table) {
            return str_starts_with($query, 'INSERT INTO `' . $table . '`') ? 'SELECT 1' : $query;
        });
    }
    if ('audit_race_settings' === get_option('kodanote_mcp_test_fault')) {
        add_filter('rest_request_after_callbacks', static function ($response, $handler, $request) {
            static $fired = false;
            global $wpdb;
            if (!$fired && '/wp/v2/settings' === $request->get_route() && 'GET' === $request->get_method()
                && $wpdb->get_var("SELECT id FROM {$wpdb->prefix}kodanote_mcp_audit WHERE status='reverting' LIMIT 1")) {
                $fired = true;
                update_option('blogdescription', 'Concurrent native edit during undo');
            }
            return $response;
        }, 10, 3);
    }
    if ('settings_partial' === get_option('kodanote_mcp_test_fault')) {
        add_filter('pre_update_option_thumbnail_size_w', static function ($value, $old_value) { return $old_value; }, 10, 2);
    }
});
PHP
cp -R "$core_source/wp-admin" "$core_source/wp-includes" "$test_root/wordpress/"
# Explicitly exclude wp-config.php, wp-content, uploads, and all source site credentials.
for core_file in index.php wp-activate.php wp-blog-header.php wp-comments-post.php wp-cron.php wp-links-opml.php wp-load.php wp-login.php wp-mail.php wp-settings.php wp-signup.php wp-trackback.php xmlrpc.php; do
    cp "$core_source/$core_file" "$test_root/wordpress/$core_file"
done
ln -s "$repo_root" "$test_root/wordpress/wp-content/plugins/kodanote-mcp"

docker run --detach --rm --name "$database_container" \
    --publish "127.0.0.1:$database_port:3306" \
    --env MYSQL_DATABASE=kodanote_mcp_test \
    --env MYSQL_ROOT_PASSWORD=kodanote_mcp_test_only \
    mysql:8.4 >/dev/null

export KODANOTE_MCP_TEST_ROOT="$test_root/wordpress"
export KODANOTE_MCP_TEST_DB_PORT="$database_port"
export KODANOTE_MCP_TEST_HTTP_PORT="$http_port"
php -r '
$deadline = microtime(true) + 60;
mysqli_report(MYSQLI_REPORT_OFF);
do {
    $db = @new mysqli("127.0.0.1", "root", "kodanote_mcp_test_only", "kodanote_mcp_test", (int) getenv("KODANOTE_MCP_TEST_DB_PORT"));
    if (!$db->connect_errno) { exit(0); }
    usleep(250000);
} while (microtime(true) < $deadline);
fwrite(STDERR, "Disposable MySQL did not become ready.\n");
exit(1);
'

cat > "$test_root/wordpress/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'kodanote_mcp_test');
define('DB_USER', 'root');
define('DB_PASSWORD', 'kodanote_mcp_test_only');
define('DB_HOST', '127.0.0.1:' . getenv('KODANOTE_MCP_TEST_DB_PORT'));
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('WP_HOME', 'http://127.0.0.1:' . getenv('KODANOTE_MCP_TEST_HTTP_PORT'));
define('WP_SITEURL', WP_HOME);
define('WP_ENVIRONMENT_TYPE', 'local');
define('WP_DEFAULT_THEME', 'mcp-test');
define('WP_DEBUG', true);
define('WP_DEBUG_DISPLAY', false);
define('WP_DEBUG_LOG', true);
define('DISABLE_WP_CRON', true);
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('KODANOTE_MCP_ALLOW_HTTP', true);
foreach (array('AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT') as $key) {
    define($key, 'integration-tests-only-' . $key);
}
$table_prefix = 'mcp_test_';
if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }
require_once ABSPATH . 'wp-settings.php';
PHP

php "$repo_root/tests/bootstrap.php" "$test_root/fixtures.json"
php -S "127.0.0.1:$http_port" -t "$test_root/wordpress" "$repo_root/tests/router.php" > "$test_root/server.log" 2>&1 &
server_pid="$!"
python3 "$repo_root/tests/integration-http.py" "http://127.0.0.1:$http_port" "$test_root/fixtures.json"
if [[ -s "$test_root/wordpress/wp-content/debug.log" ]]; then
    printf '\nWordPress debug output:\n'
    head -n 20 "$test_root/wordpress/wp-content/debug.log"
    exit 1
fi
