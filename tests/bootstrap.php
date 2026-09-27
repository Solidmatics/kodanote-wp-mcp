<?php
/** Install an isolated, disposable WordPress database and permission fixtures. */

if (PHP_SAPI !== 'cli' || !getenv('KODANOTE_MCP_TEST_ROOT')) {
    exit("This script only runs in the integration test harness.\n");
}

define('WP_INSTALLING', true);
require getenv('KODANOTE_MCP_TEST_ROOT') . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
add_filter('pre_wp_mail', '__return_true');

if (is_blog_installed()) {
    throw new RuntimeException('Refusing to overwrite an existing WordPress installation.');
}

wp_install('Kodanote MCP integration tests', 'mcp_admin', 'mcp-admin@example.test', true, '', 'integration-only-password');
update_option('permalink_structure', '/%postname%/');
update_option('blog_public', 0);
update_option('timezone_string', 'UTC');

$activation = activate_plugin('kodanote-mcp/kodanote-mcp.php');
if (is_wp_error($activation)) {
    throw new RuntimeException($activation->get_error_message());
}
flush_rewrite_rules(false);

$users = array('admin' => get_user_by('login', 'mcp_admin')->ID);
add_role('taxonomy_manager', 'Taxonomy-only fixture', array('read' => true, 'manage_categories' => true));
add_role('audit_manager', 'Audit-only administration fixture', array('read' => true, 'manage_options' => true));
add_role('design_without_css', 'Appearance without CSS fixture', array(
    'read' => true, 'manage_options' => true, 'edit_theme_options' => true, 'unfiltered_html' => false,
));
foreach (array('contributor', 'author', 'editor', 'taxonomy_manager') as $role) {
    $id = wp_insert_user(array(
        'user_login' => 'mcp_' . $role,
        'user_pass' => 'integration-only-password',
        'user_email' => $role . '@example.test',
        'role' => $role,
    ));
    if (is_wp_error($id)) {
        throw new RuntimeException($id->get_error_message());
    }
    $users[$role] = $id;
}

$posts = array();
foreach (array('contributor', 'author') as $role) {
    $posts[$role . '_draft'] = wp_insert_post(array(
        'post_title' => ucfirst($role) . ' private draft fixture',
        'post_content' => 'Confidential ' . $role . ' draft content.',
        'post_status' => 'draft',
        'post_author' => $users[$role],
    ), true);
    if (is_wp_error($posts[$role . '_draft'])) {
        throw new RuntimeException($posts[$role . '_draft']->get_error_message());
    }
}
$posts['author_private'] = wp_insert_post(array(
    'post_title' => 'Private published fixture',
    'post_content' => 'Private content only authorized readers may see.',
    'post_status' => 'private',
    'post_author' => $users['author'],
), true);
$posts['public'] = wp_insert_post(array(
    'post_title' => 'Public fixture',
    'post_content' => 'Publicly visible integration fixture.',
    'post_status' => 'publish',
    'post_author' => $users['author'],
), true);
foreach (array('home', 'blog', 'draft_page') as $page) {
    $posts[$page] = wp_insert_post(array(
        'post_type' => 'page', 'post_title' => 'Settings fixture ' . $page,
        'post_status' => 'draft_page' === $page ? 'draft' : 'publish',
        'post_author' => $users['admin'], 'post_content' => 'Homepage/blog settings test.',
    ), true);
    if (is_wp_error($posts[$page])) { throw new RuntimeException($posts[$page]->get_error_message()); }
}

// Deliberate user overrides must survive narrowly scoped appearance edits.
wp_set_current_user($users['admin']);
$navigation_id = wp_insert_post(array(
    'post_type' => 'wp_navigation',
    'post_title' => 'Fixture primary navigation',
    'post_status' => 'publish',
    'post_author' => $users['admin'],
    'post_content' => wp_slash('<!-- wp:navigation-link {"label":"Home","url":"/","kind":"custom"} /--><!-- wp:navigation-submenu {"label":"More"} --><!-- wp:navigation-link {"label":"About","url":"/about/","kind":"custom"} /--><!-- /wp:navigation-submenu -->'),
), true);
if (is_wp_error($navigation_id)) {
    throw new RuntimeException($navigation_id->get_error_message());
}
$fixture_theme = get_stylesheet_directory();
$header_path = $fixture_theme . '/parts/header.html';
file_put_contents($header_path, str_replace('"ref":0', '"ref":' . $navigation_id, file_get_contents($header_path)));
$global_styles_id = WP_Theme_JSON_Resolver::get_user_global_styles_post_id();
$global_styles = wp_update_post(array(
    'ID' => $global_styles_id,
    'post_content' => wp_slash(wp_json_encode(array(
        'version' => 3,
        'isGlobalStylesUserThemeJSON' => true,
        'settings' => array(
            'color' => array('palette' => array(array('slug' => 'secondary', 'name' => 'Custom secondary', 'color' => '#abcdef'))),
            'typography' => array('lineHeight' => true),
        ),
        'styles' => array('typography' => array('lineHeight' => '1.7')),
    ))),
), true);
if (is_wp_error($global_styles)) {
    throw new RuntimeException($global_styles->get_error_message());
}

$attachment_id = wp_insert_attachment(array(
    'post_title' => 'Author image fixture',
    'post_excerpt' => 'Image caption fixture',
    'post_content' => 'Image description fixture',
    'post_status' => 'inherit',
    'post_mime_type' => 'image/png',
    'post_author' => $users['author'],
    'guid' => home_url('/wp-content/uploads/fixture.png'),
), '', 0, true);
if (is_wp_error($attachment_id)) {
    throw new RuntimeException($attachment_id->get_error_message());
}
update_post_meta($attachment_id, '_wp_attachment_image_alt', 'Original fixture alt text');
$editor_attachment_id = wp_insert_attachment(array(
    'post_title' => 'Editor image fixture',
    'post_status' => 'inherit',
    'post_mime_type' => 'image/png',
    'post_author' => $users['editor'],
    'guid' => home_url('/wp-content/uploads/editor-fixture.png'),
), '', 0, true);
if (is_wp_error($editor_attachment_id)) {
    throw new RuntimeException($editor_attachment_id->get_error_message());
}

$application_password = WP_Application_Passwords::create_new_application_password(
    $users['editor'], array('name' => 'Integration fixture only')
);
if (is_wp_error($application_password)) {
    throw new RuntimeException($application_password->get_error_message());
}

file_put_contents($argv[1], wp_json_encode(array(
    'users' => $users,
    'posts' => $posts,
    'global_styles' => $global_styles_id,
    'navigation' => $navigation_id,
    'footer_content' => file_get_contents($fixture_theme . '/parts/footer.html'),
    'header_content' => file_get_contents($header_path),
    'attachment' => $attachment_id,
    'editor_attachment' => $editor_attachment_id,
    'application_password' => $application_password[0],
), JSON_PRETTY_PRINT));
echo "Installed isolated WordPress " . get_bloginfo('version') . " with test fixtures.\n";
