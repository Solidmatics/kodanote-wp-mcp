#!/usr/bin/env python3
"""Real HTTP integration checks against a disposable WordPress installation."""

import base64
import hashlib
import http.cookiejar
import json
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


BASE = sys.argv[1].rstrip("/")
FIXTURES = json.load(open(sys.argv[2], encoding="utf-8"))
API = BASE + "/wp-json/kodanote-mcp/v1"
RESOURCE = API + "/mcp"
REDIRECT = "https://client.example.test/callback"
CHECKS = 0
ALL_SCOPES = "content:read content:write appearance:read appearance:write settings:read settings:write plugins:read users:read media:read media:write audit:read audit:write"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies), NoRedirect()
        )

    def request(self, url, method="GET", body=None, headers=None, form=False):
        outgoing = dict(headers or {})
        if body is not None:
            outgoing["Content-Type"] = (
                "application/x-www-form-urlencoded" if form else "application/json"
            )
            body = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
        request = urllib.request.Request(url, data=body, method=method, headers=outgoing)
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read().decode("utf-8", errors="replace")
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            result = raw
        return response.status, response.headers, result


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}
        self.action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs.get("action")
        if tag == "input" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")


class CompletionParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.links = []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self.scripts.append({"nonce": attrs.get("nonce"), "body": ""})
            self.in_script = True
        if tag == "a":
            self.links.append(attrs.get("href"))

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts[-1]["body"] += data


def consent_callback(status, headers, html):
    check(status == 200 and not headers.get("Location"),
          "consent finishes on the same origin without a form redirect chain")
    parser = CompletionParser()
    parser.feed(html)
    check(len(parser.scripts) == 1, "completion has exactly one navigation script")
    script = parser.scripts[0]
    nonce = script["nonce"]
    policy = headers.get("Content-Security-Policy", "")
    check(nonce and re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce)
          and policy == "default-src 'none'; script-src 'nonce-" + nonce
          + "'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
          "completion permits only its nonced script and keeps form and frame restrictions")
    match = re.fullmatch(r"window\.location\.replace\((.+)\);", script["body"])
    check(match is not None, "callback navigation replaces the completed consent page")
    callback = json.loads(match.group(1))
    check(parser.links == [callback], "script and no-JavaScript fallback use the same callback")
    check("no-store" in headers.get("Cache-Control", "")
          and headers.get("Referrer-Policy") == "no-referrer"
          and headers.get("X-Frame-Options") == "DENY",
          "completion prevents caching, referrer leakage and framing")
    return callback


def check(condition, message):
    global CHECKS
    if not condition:
        raise AssertionError(message)
    CHECKS += 1
    print("PASS " + message)


def json_error(response, error=None):
    status, _, body = response
    return status >= 400 and isinstance(body, dict) and (
        error is None or body.get("error", body.get("code")) == error
    )


def register(client, name="Integration client", auth="none", redirect=REDIRECT):
    status, _, body = client.request(
        API + "/oauth/register", "POST",
        {"client_name": name, "redirect_uris": [redirect],
         "token_endpoint_auth_method": auth,
         "grant_types": ["authorization_code", "refresh_token"],
         "response_types": ["code"]},
    )
    check(status == 201 and isinstance(body, dict) and "client_id" in body,
          "register " + auth + " OAuth client")
    return body


def login(role):
    client = Client()
    client.request(BASE + "/wp-login.php")
    status, _, body = client.request(
        BASE + "/wp-login.php", "POST",
        {"log": "mcp_" + role, "pwd": "integration-only-password",
         "wp-submit": "Log In", "redirect_to": BASE + "/wp-admin/",
         "testcookie": "1"}, form=True,
    )
    check(status == 302 and any("wordpress_logged_in" in cookie.name for cookie in client.cookies),
          "WordPress login as " + role)
    return client


def authorize(session, registration, scope="content:read content:write", decision="allow", tamper_nonce=False, other_session=None, selected_scopes=None, extra_fields=None, state=None):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(16) if state is None else state
    redirect = registration["redirect_uris"][0]
    parameters = {
        "action": "kodanote_mcp_authorize", "response_type": "code",
        "client_id": registration["client_id"], "redirect_uri": redirect,
        "scope": scope, "state": state, "resource": RESOURCE,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    url = BASE + "/wp-admin/admin-post.php?" + urllib.parse.urlencode(parameters)
    status, headers, html = session.request(url)
    check(status == 200 and isinstance(html, str) and "_wpnonce" in html,
          "authorization requires rendered consent")
    parser = FormParser()
    parser.feed(html)
    check("form-action 'self';" in headers.get("Content-Security-Policy", "")
          and "script-src" not in headers.get("Content-Security-Policy", "")
          and parser.action.startswith("/") and not parser.action.startswith("//"),
          "consent form stays on the current origin under its restrictive policy")
    parser.fields["decision"] = decision
    if selected_scopes is not None:
        selected_fields = {"scope_" + item.replace(":", "_") for item in selected_scopes}
        parser.fields = {name: value for name, value in parser.fields.items()
                         if not name.startswith("scope_") or name == "scope_selection" or name in selected_fields}
    parser.fields.update(extra_fields or {})
    target = urllib.parse.urljoin(url, parser.action or url)
    if tamper_nonce:
        bad_fields = dict(parser.fields, _wpnonce="invalid-nonce")
        check(session.request(target, "POST", bad_fields, form=True)[0] == 403,
              "consent rejects an invalid CSRF nonce")
    if other_session is not None:
        check(other_session.request(target, "POST", parser.fields, form=True)[0] == 403,
              "consent is bound to its original WordPress user and session")
    status, headers, html = session.request(
        target, "POST", parser.fields, form=True
    )
    destination = urllib.parse.urlparse(consent_callback(status, headers, html))
    query = urllib.parse.parse_qs(destination.query)
    expected = urllib.parse.urlparse(redirect)
    check((destination.scheme, destination.netloc, destination.path)
          == (expected.scheme, expected.netloc, expected.path)
          and query.get("state") == [state], "consent preserves registered redirect and state")
    check(all(query.get(key) == value for key, value in urllib.parse.parse_qs(expected.query).items()),
          "callback preserves registered query parameters")
    if decision == "deny" or selected_scopes == []:
        check(query.get("error") == ["access_denied"] and "code" not in query,
              "denied consent does not issue an authorization code")
        return None
    check("code" in query, "approved consent issues an authorization code")
    return {"grant_type": "authorization_code", "code": query["code"][0],
            "redirect_uri": redirect, "client_id": registration["client_id"],
            "code_verifier": verifier, "resource": RESOURCE}


def token(client, fields, headers=None):
    return client.request(API + "/oauth/token", "POST", fields, headers, form=True)


def grant(session, registration, scope="content:read content:write"):
    fields = authorize(session, registration, scope)
    status, _, body = token(session, fields)
    check(status == 200 and isinstance(body, dict) and "access_token" in body
          and "refresh_token" in body, "PKCE authorization code exchanges for tokens (HTTP %s, %s)" %
          (status, body.get("error", body.get("code", "success")) if isinstance(body, dict) else "non-JSON response"))
    return body, fields


def rpc(client, access, method, params=None, rpc_id=1, extra_headers=None):
    headers = {"Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-03-26"}
    if access:
        headers["Authorization"] = "Bearer " + access
    headers.update(extra_headers or {})
    body = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
    if params is not None:
        body["params"] = params
    return client.request(RESOURCE, "POST", body, headers)


def tool(client, access, name, arguments=None):
    return rpc(client, access, "tools/call", {"name": name, "arguments": arguments or {}})


def tool_ok(response):
    status, _, body = response
    return status == 200 and isinstance(body, dict) and "result" in body and not body["result"].get("isError", False)


def tool_result(response):
    result = response[2]["result"]
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


def names_for(client, access):
    response = rpc(client, access, "tools/list")
    check(response[0] == 200 and "result" in response[2], "role-scoped token can discover tools")
    return {item["name"] for item in response[2]["result"]["tools"]}


def assert_tool(client, access, name, arguments=None):
    response = tool(client, access, name, arguments)
    check(tool_ok(response), name + (" succeeds" if tool_ok(response) else " failed: " + str(response[2])))
    return tool_result(response)


def colors_in(palettes):
    """WordPress exposes per-origin palettes in merged theme.json settings."""
    colors = {}
    if isinstance(palettes, list):
        for item in palettes:
            if isinstance(item, dict) and "slug" in item and "color" in item:
                colors[item["slug"]] = item["color"]
    elif isinstance(palettes, dict):
        for value in palettes.values():
            colors.update(colors_in(value))
    return colors


def set_fixture_role(user_id, role):
    """Change only disposable harness fixtures to verify live permission changes."""
    subprocess.run(["php", "-r", r'''
        $root = getenv('KODANOTE_MCP_TEST_ROOT');
        if (!$root || !str_contains($root, '/kodanote-mcp-test.')) { exit(1); }
        require $root . '/wp-load.php';
        $user = get_user_by('id', (int) $argv[1]);
        if (!$user || !str_starts_with($user->user_login, 'mcp_')) { exit(1); }
        $user->set_role($argv[2]);
    ''', str(user_id), role], check=True, capture_output=True, text=True)


def fixture_storage(post_id=0):
    """Independently read persisted fixture content and immutable theme sources."""
    result = subprocess.run(["php", "-r", r'''
        $root = getenv('KODANOTE_MCP_TEST_ROOT');
        if (!$root || !str_contains($root, '/kodanote-mcp-test.')) { exit(1); }
        require $root . '/wp-load.php';
        $theme = get_stylesheet_directory();
        $post = (int) $argv[1] ? get_post((int) $argv[1]) : null;
        echo wp_json_encode(array(
            'footer_file' => file_get_contents($theme . '/parts/footer.html'),
            'header_file' => file_get_contents($theme . '/parts/header.html'),
            'post_type' => $post ? $post->post_type : null,
            'post_content' => $post ? $post->post_content : null,
        ));
    ''', str(post_id)], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def fixture_global_styles(configuration=None, theme=None):
    """Read or restore only disposable theme fixtures, including native CSS output."""
    result = subprocess.run(["php", "-r", r'''
        $root = getenv('KODANOTE_MCP_TEST_ROOT');
        if (!$root || !str_contains($root, '/kodanote-mcp-test.')) { exit(1); }
        require $root . '/wp-load.php';
        wp_set_current_user((int) $argv[1]);
        if ($argv[3]) {
            if (!in_array($argv[3], array('mcp-test', 'mcp-css-empty'), true)) { exit(1); }
            switch_theme($argv[3]);
        }
        if (!in_array(get_stylesheet(), array('mcp-test', 'mcp-css-empty'), true)) { exit(1); }
        $record = WP_Theme_JSON_Resolver::get_user_data_from_wp_global_styles(wp_get_theme(), false);
        if ($argv[2]) {
            $config = json_decode($argv[2], true, 512, JSON_THROW_ON_ERROR);
            if (!$record || empty($config['isGlobalStylesUserThemeJSON'])) { exit(1); }
            $saved = wp_update_post(array('ID' => $record['ID'], 'post_content' => wp_slash(wp_json_encode($config))), true);
            if (is_wp_error($saved)) { throw new RuntimeException($saved->get_error_message()); }
        }
        wp_clean_theme_json_cache();
        $record = WP_Theme_JSON_Resolver::get_user_data_from_wp_global_styles(wp_get_theme(), false);
        echo wp_json_encode(array(
            'id' => (int) ($record['ID'] ?? 0),
            'config' => isset($record['post_content']) ? json_decode($record['post_content'], true) : null,
            'stylesheet' => wp_get_global_stylesheet(array('custom-css')),
        ));
    ''', str(FIXTURES["users"]["admin"]),
        json.dumps(configuration) if configuration is not None else "", theme or ""],
        check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def fixture_fault(value):
    subprocess.run(["php", "-r", r'''
        require getenv('KODANOTE_MCP_TEST_ROOT') . '/wp-load.php';
        if ($argv[1]) { update_option('kodanote_mcp_test_fault', $argv[1]); }
        else { delete_option('kodanote_mcp_test_fault'); }
    ''', value], check=True, capture_output=True, text=True)


def fixture_comment(post_id, comment_id=0, status="1"):
    result = subprocess.run(["php", "-r", r'''
        require getenv('KODANOTE_MCP_TEST_ROOT') . '/wp-load.php';
        $id = (int) $argv[2];
        if (!$id) {
            $id = wp_insert_comment(array('comment_post_ID' => (int) $argv[1],
                'comment_author' => 'Moderation fixture', 'comment_content' => 'Preserve moderation state',
                'comment_approved' => $argv[3]));
        } elseif ('__read' !== $argv[3]) { wp_update_comment(array('comment_ID' => $id, 'comment_approved' => $argv[3])); }
        echo wp_json_encode(array('id' => $id, 'status' => get_comment($id)->comment_approved));
    ''', str(post_id), str(comment_id), status], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def main():
    client = Client()
    for _ in range(60):
        try:
            metadata = client.request(API + "/oauth/metadata")
            break
        except urllib.error.URLError:
            time.sleep(0.1)
    else:
        raise RuntimeError("WordPress HTTP server did not become ready")
    check(metadata[0] == 200 and "S256" in metadata[2].get("code_challenge_methods_supported", []),
          "OAuth discovery advertises S256 PKCE")
    status, _, body = client.request(API + "/oauth/resource-metadata")
    check(status == 200 and body.get("resource") == RESOURCE,
          "protected resource metadata identifies the MCP audience")
    status, _, body = client.request(BASE + "/.well-known/oauth-authorization-server")
    check(status == 200 and body.get("issuer") == BASE,
          "well-known authorization server discovery works")
    status, _, body = client.request(BASE + "/.well-known/oauth-protected-resource/wp-json/kodanote-mcp/v1/mcp")
    check(status == 200 and body.get("resource") == RESOURCE,
          "path-qualified protected resource discovery works")
    status, headers, _ = rpc(client, None, "tools/list")
    check(status == 401 and "resource_metadata=" in headers.get("WWW-Authenticate", ""),
          "anonymous MCP requests receive OAuth resource discovery challenge")
    bad = client.request(API + "/oauth/register", "POST",
                         {"redirect_uris": ["http://attacker.example/callback"]})
    check(json_error(bad), "registration rejects insecure non-loopback redirects")
    bad = client.request(API + "/oauth/register", "POST",
                         {"redirect_uris": [REDIRECT + "#fragment"]})
    check(json_error(bad), "registration rejects redirect fragments")
    bad = client.request(API + "/oauth/register", "POST",
                         {"redirect_uris": [REDIRECT], "grant_types": ["authorization_code", []]})
    check(json_error(bad), "registration rejects malformed grant type values")
    status, _, minimal = client.request(API + "/oauth/register", "POST", {"redirect_uris": [REDIRECT]})
    check(status == 201 and minimal.get("token_endpoint_auth_method") == "client_secret_basic"
          and minimal.get("grant_types") == ["authorization_code"] and "client_secret" in minimal,
          "minimal client registration uses RFC 7591 authentication and grant defaults")

    registration = register(client)
    other_registration = register(client, "Other integration client")
    contributor = login("contributor")
    author = login("author")
    check(rpc(contributor, None, "tools/list")[0] == 401,
          "WordPress login cookies do not substitute for MCP bearer authorization")
    authorize(contributor, registration, decision="deny")
    authorize(contributor, registration, tamper_nonce=True, other_session=author)
    authorize(contributor, registration, selected_scopes=[])
    for callback in (
        'https://client.example.test:9443/callback?next=%2Fconnect&label=%22%3C%2Fscript%3E%26',
        'http://127.0.0.1:43129/callback',
        'http://[::1]:43129/callback',
    ):
        callback_client = register(client, redirect=callback)
        fields = authorize(contributor, callback_client, state='quote"</script><script>bad()</script>&')
        check(token(client, fields)[0] == 200, "callback variant completes authorization and PKCE exchange")
    credentials, used_fields = grant(contributor, registration)
    check(json_error(token(client, used_fields)), "authorization codes cannot be replayed")
    check(rpc(client, credentials["access_token"], "tools/list")[0] == 401,
          "authorization code replay revokes tokens issued from that code")
    credentials, _ = grant(contributor, registration)

    for field, value, label in (
        ("code_verifier", "x" * 64, "PKCE verifier"),
        ("resource", "https://attacker.example/mcp", "resource audience"),
        ("redirect_uri", REDIRECT + "/different", "redirect URI"),
        ("client_id", other_registration["client_id"], "client identity"),
    ):
        fields = authorize(contributor, registration)
        fields[field] = value
        check(json_error(token(client, fields)), "code exchange binds " + label)

    access = credentials["access_token"]
    status, _, body = rpc(client, access, "initialize", {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "integration-tests", "version": "1.0"},
    })
    check(status == 200 and body.get("result", {}).get("protocolVersion") == "2025-03-26",
          "authenticated MCP client initializes")
    instructions = body["result"].get("instructions", "")
    check(all(phrase in instructions for phrase in ("core/html", "list_block_patterns", "synced pattern", "get_global_styles", "alt text", "untrusted")),
          "initialize instructions steer clients to blocks, patterns, theme presets and accessible content")
    response = client.request(RESOURCE, "POST", {"jsonrpc": "2.0", "method": "notifications/initialized"},
                              {"Authorization": "Bearer " + access,
                               "Accept": "application/json, text/event-stream"})
    check(response[0] == 202 and response[2] == "",
          "MCP notification acknowledgement has an empty HTTP body")
    status, _, body = rpc(client, access, "tools/list")
    check(status == 200 and isinstance(body.get("result", {}).get("tools"), list),
          "authenticated MCP client discovers tools")
    tool_names = {item["name"] for item in body["result"]["tools"]}
    permission_tests(client, contributor, author, registration, credentials, tool_names)
    expanded_permission_tests(client, contributor, author, registration, credentials)
    response = rpc(client, access, "tools/list", extra_headers={"Origin": "https://attacker.example"})
    check(response[0] == 403 and not response[1].get("Access-Control-Allow-Origin"),
          "untrusted browser origins receive no MCP CORS access")
    response = client.request(RESOURCE, "OPTIONS", headers={"Origin": "https://attacker.example"})
    check(response[0] == 403 and not response[1].get("Access-Control-Allow-Origin"),
          "untrusted browser preflights cannot bypass MCP origin checks")
    response = rpc(client, access, "tools/list", extra_headers={"Origin": "https://claude.ai"})
    check(response[0] == 200 and response[1].get("Access-Control-Allow-Origin") == "https://claude.ai"
          and not response[1].get("Access-Control-Allow-Credentials"),
          "Claude origin receives bearer-only MCP CORS access")

    rotating, _ = grant(contributor, registration)
    refresh_fields = {"grant_type": "refresh_token", "refresh_token": rotating["refresh_token"],
                      "client_id": registration["client_id"], "resource": RESOURCE}
    wrong_client = dict(refresh_fields, client_id=other_registration["client_id"])
    check(json_error(token(client, wrong_client)), "refresh token binds client identity")
    wrong_resource = dict(refresh_fields, resource="https://attacker.example/mcp")
    check(json_error(token(client, wrong_resource)), "refresh token binds resource audience")
    status, _, refreshed = token(client, refresh_fields)
    check(status == 200 and refreshed.get("refresh_token") != rotating["refresh_token"],
          "refresh tokens rotate on use")
    check(json_error(token(client, refresh_fields)), "refresh token reuse is rejected")
    check(rpc(client, refreshed["access_token"], "tools/list")[0] == 401,
          "refresh token replay revokes the entire token family")

    revoked, _ = grant(contributor, registration)
    status, _, _ = client.request(API + "/oauth/revoke", "POST",
                                 {"client_id": registration["client_id"],
                                  "token": revoked["access_token"]}, form=True)
    check(status == 200, "OAuth token revocation succeeds")
    check(rpc(client, revoked["access_token"], "tools/list")[0] == 401,
          "revoked access tokens cannot call MCP")

    confidential = register(client, "Confidential client", "client_secret_basic")
    fields = authorize(contributor, confidential)
    check(json_error(token(client, fields)), "confidential client requires its secret")
    fields = authorize(contributor, confidential)
    secret = base64.b64encode((confidential["client_id"] + ":" + confidential["client_secret"]).encode()).decode()
    status, _, body = token(client, fields, {"Authorization": "Basic " + secret})
    check(status == 200 and "access_token" in body,
          "confidential client can exchange codes with HTTP Basic authentication")
    fields = authorize(contributor, confidential)
    status, _, body = client.request(BASE + "/index.php?rest_route=/kodanote-mcp/v1/oauth/token", "POST",
                                     fields, {"Authorization": "Basic " + secret}, form=True)
    check(status == 200 and "access_token" in body,
          "query-form OAuth routes accept confidential client Basic authentication")
    confidential_post = register(client, "Confidential body-auth client", "client_secret_post")
    fields = authorize(contributor, confidential_post)
    fields["client_secret"] = confidential_post["client_secret"]
    status, _, body = token(client, fields)
    check(status == 200 and "access_token" in body,
          "confidential client can exchange codes with client_secret_post authentication")
    admin_registration = register(client, "Admin revoke fixture")
    admin_tokens, _ = grant(contributor, admin_registration)
    page_url = BASE + "/wp-admin/profile.php?page=kodanote-mcp"
    status, _, html = contributor.request(page_url)
    check(status == 200 and isinstance(html, str) and "Admin revoke fixture" in html,
          "contributor can manage their MCP connections")
    rows = re.findall(r"<tr>.*?</tr>", html, re.DOTALL)
    row = next(row for row in rows if "Admin revoke fixture" in row)
    parser = FormParser()
    parser.feed(row)
    status, headers, _ = contributor.request(parser.action, "POST", parser.fields, form=True)
    location = headers.get("Location", "")
    check(status == 302 and "/profile.php?page=kodanote-mcp" in location
          and contributor.request(location)[0] == 200,
          "contributor revocation redirects back to an accessible connections page")
    check(rpc(client, admin_tokens["access_token"], "tools/list")[0] == 401,
          "WordPress connections page immediately revokes MCP access")
    application_secret = base64.b64encode(("mcp_editor:" + FIXTURES["application_password"]).encode()).decode()
    status, _, body = client.request(BASE + "/wp-json/wp/v2/users/me", headers={"Authorization": "Basic " + application_secret})
    check(status == 200 and body.get("id") == FIXTURES["users"]["editor"],
          "WordPress application passwords still authenticate unrelated REST routes")
    status, _, body = client.request(BASE + "/index.php?rest_route=/wp/v2/users/me", headers={"Authorization": "Basic " + application_secret})
    check(status == 200 and body.get("id") == FIXTURES["users"]["editor"],
          "query-form WordPress REST routes retain application-password authentication")
    status, _, body = client.request(API + "/oauth/token?rest_route=/wp/v2/users/me", headers={"Authorization": "Basic " + application_secret})
    check(status == 200 and body.get("id") == FIXTURES["users"]["editor"],
          "explicit core rest_route takes precedence over an OAuth-looking URL path")
    print("\nAll %d real WordPress HTTP integration checks passed." % CHECKS)


def permission_tests(client, contributor, author, registration, credentials, tool_names):
    required = {"list_content", "get_content", "create_content", "update_content", "trash_content"}
    check(required.issubset(tool_names), "MCP exposes content discovery and editing tools")
    access = credentials["access_token"]
    own_draft = FIXTURES["posts"]["contributor_draft"]
    other_draft = FIXTURES["posts"]["author_draft"]
    private_post = FIXTURES["posts"]["author_private"]
    response = tool(client, access, "get_content", {"id": own_draft})
    check(tool_ok(response) and tool_result(response).get("id") == own_draft,
          "contributor can read their own unpublished draft")
    check(not tool_ok(tool(client, access, "get_content", {"id": other_draft})),
          "contributor cannot read another author's draft")
    check(not tool_ok(tool(client, access, "get_content", {"id": private_post})),
          "contributor cannot read another author's private post")
    response = tool(client, access, "list_content", {"status": "any", "per_page": 50})
    check(tool_ok(response), "contributor can list content they may access")
    ids = {item["id"] for item in tool_result(response)["items"]}
    check(own_draft in ids and other_draft not in ids and private_post not in ids,
          "content listing does not leak other authors' drafts or private posts")
    check(not tool_ok(tool(client, access, "create_content",
                           {"title": "Forbidden publish", "status": "publish"})),
          "contributor cannot publish through MCP")
    check(not tool_ok(tool(client, access, "update_content",
                           {"id": own_draft, "status": "publish"})),
          "contributor cannot publish an existing draft through MCP")
    check(not tool_ok(tool(client, access, "create_content",
                           {"post_type": "page", "title": "Forbidden page"})),
          "contributor cannot create pages through MCP")
    response = tool(client, access, "create_content", {"title": "Created draft", "content": "Draft body"})
    check(tool_ok(response) and tool_result(response).get("status") == "draft",
          "content creation defaults to draft")
    created_id = tool_result(response)["id"]
    response = tool(client, access, "update_content", {"id": created_id, "title": "Updated draft"})
    check(tool_ok(response) and tool_result(response).get("title") == "Updated draft",
          "contributor can update their own draft")
    response = tool(client, access, "trash_content", {"id": created_id})
    check(tool_ok(response), "contributor can move their own draft to trash")

    readonly, _ = grant(contributor, registration, "content:read")
    response = rpc(client, readonly["access_token"], "tools/list")
    readonly_tools = {item["name"] for item in response[2].get("result", {}).get("tools", [])}
    check("get_content" in readonly_tools and not readonly_tools.intersection({"create_content", "update_content", "trash_content"}),
          "read-only OAuth grant only discovers read tools")
    check(tool_ok(tool(client, readonly["access_token"], "get_content", {"id": own_draft})),
          "read-only OAuth grant can read authorized content")
    check(not tool_ok(tool(client, readonly["access_token"], "create_content", {"title": "No write scope"})),
          "read-only OAuth grant cannot create content")
    check(not tool_ok(tool(client, readonly["access_token"], "update_content", {"id": own_draft, "title": "No write scope"})),
          "read-only OAuth grant cannot update content")

    author_tokens, _ = grant(author, registration)
    author_access = author_tokens["access_token"]
    response = tool(client, author_access, "create_content", {"title": "Author published", "status": "publish"})
    check(tool_ok(response) and tool_result(response).get("status") == "publish",
          "author may publish their own post with write scope")
    check(not tool_ok(tool(client, author_access, "update_content", {"id": own_draft, "title": "Cross-author edit"})),
          "author cannot edit another user's post")
    check(not tool_ok(tool(client, author_access, "trash_content", {"id": own_draft})),
          "author cannot trash another user's post")


def expanded_permission_tests(client, contributor, author, registration, content_credentials):
    admin = login("admin")
    editor = login("editor")
    admin_tokens, _ = grant(admin, registration, ALL_SCOPES)
    editor_tokens, _ = grant(editor, registration, ALL_SCOPES)
    author_tokens, _ = grant(author, registration, ALL_SCOPES)
    contributor_tokens, _ = grant(contributor, registration, ALL_SCOPES)
    admin_access = admin_tokens["access_token"]
    editor_access = editor_tokens["access_token"]
    author_access = author_tokens["access_token"]
    contributor_access = contributor_tokens["access_token"]
    content_access = content_credentials["access_token"]

    taxonomy_manager = login("taxonomy_manager")
    taxonomy_tokens, _ = grant(taxonomy_manager, registration)
    taxonomy_tools = names_for(client, taxonomy_tokens["access_token"])
    check("create_term" in taxonomy_tools and "create_content" not in taxonomy_tools,
          "custom taxonomy-only role discovers taxonomy tools without content creation")
    assert_tool(client, taxonomy_tokens["access_token"], "create_term", {"name": "Custom role category"})
    check(not tool_ok(tool(client, taxonomy_tokens["access_token"], "create_content", {"title": "Forbidden custom role draft"})),
          "custom taxonomy-only role cannot invoke a crafted content mutation")

    check(set(admin_tokens["scope"].split()) == set(ALL_SCOPES.split()),
          "administrator may explicitly consent to every supported scope")
    for role, credentials in (("editor", editor_tokens), ("author", author_tokens), ("contributor", contributor_tokens)):
        check(not set(credentials["scope"].split()).intersection(
            {"appearance:write", "settings:read", "settings:write", "plugins:read", "users:read", "audit:read", "audit:write"}),
            role + " cannot authorize administrator scopes")
    check(not set(contributor_tokens["scope"].split()).intersection({"media:read", "media:write"}),
          "contributor cannot authorize media scopes without upload_files")
    check({"appearance:read", "media:read", "media:write"}.issubset(editor_tokens["scope"].split()),
          "editor receives appearance inspection and media scopes")
    selected = authorize(admin, registration, ALL_SCOPES, selected_scopes=["appearance:read"])
    status, _, selected_tokens = token(admin, selected)
    check(status == 200 and selected_tokens.get("scope") == "appearance:read",
          "granular consent issues only explicitly selected scope")
    read_only_fields = authorize(admin, registration, ALL_SCOPES, decision="read")
    status, _, read_only_tokens = token(admin, read_only_fields)
    check(status == 200 and not any(item.endswith(":write") for item in read_only_tokens.get("scope", "").split())
          and "plugins:read" in read_only_tokens.get("scope", "").split(),
          "read-only consent retains requested read families and strips every write scope")
    escalation = authorize(contributor, registration, ALL_SCOPES, extra_fields={
        "scope_settings_read": "1", "scope_settings_write": "1", "scope_plugins_read": "1"})
    status, _, escalation_tokens = token(contributor, escalation)
    check(status == 200 and not {"settings:read", "settings:write", "plugins:read"}.intersection(
        escalation_tokens.get("scope", "").split()), "forged consent fields cannot add role-forbidden scopes")

    admin_tools = names_for(client, admin_access)
    editor_tools = names_for(client, editor_access)
    contributor_tools = names_for(client, contributor_access)
    privileged = {"update_global_styles", "list_templates", "get_template", "update_template", "create_template",
                  "get_layout", "update_layout", "list_navigation", "get_navigation", "create_navigation", "update_navigation",
                  "get_site_settings", "update_site_settings", "list_plugins", "list_users",
                  "list_audit_log", "get_audit_entry", "revert_audit_entry"}
    check(privileged.issubset(admin_tools), "administrator discovers scoped appearance and administration tools")
    check(not privileged.intersection(editor_tools), "editor tool discovery hides administrator operations")
    check({"get_theme", "get_global_styles", "list_media", "get_media", "update_media"}.issubset(editor_tools),
          "editor discovers theme inspection and media tools")
    check(not {"list_media", "get_media", "update_media"}.intersection(contributor_tools),
          "contributor tool discovery hides media operations")
    content_tools = names_for(client, content_access)
    check(not {"get_global_styles", "list_media", "get_site_settings", "list_plugins", "list_users"}.intersection(content_tools),
          "existing content-only grant gains no appearance or administration access")
    for name in ("get_global_styles", "get_site_settings", "list_plugins", "list_users", "list_media"):
        check(not tool_ok(tool(client, content_access, name)),
              "content-only grant cannot invoke " + name)

    assert_tool(client, editor_access, "get_theme")
    styles = assert_tool(client, editor_access, "get_global_styles")
    colors = colors_in(styles["settings"]["color"]["palette"])
    check(colors.get("primary") == "#112233" and colors.get("secondary") == "#abcdef",
          "theme inspection combines theme.json colors with user palette overrides")
    check(styles.get("writable") is False, "editor sees global styles as read-only")
    before = assert_tool(client, admin_access, "get_global_styles")
    check(before.get("writable") is True and before["version"],
          "administrator receives writable global styles and a concurrency version")
    check(not tool_ok(tool(client, editor_access, "update_global_styles", {
        "version": before["version"], "background_color": "#ff0000"})),
          "editor cannot invoke a crafted global styles mutation")
    changed = assert_tool(client, admin_access, "update_global_styles", {
        "version": before["version"], "palette": [
            {"slug": "secondary", "name": "Edited secondary", "color": "#123abc"}],
        "background_color": "#fefefe"})
    check(changed["version"] != before["version"], "global styles edit updates its concurrency version")
    check(changed["user"]["settings"]["typography"] == before["user"]["settings"]["typography"]
          and changed["user"]["styles"]["typography"] == before["user"]["styles"]["typography"],
          "palette edit preserves unrelated typography settings and styles")
    check(not tool_ok(tool(client, admin_access, "update_global_styles", {
        "version": before["version"], "text_color": "#ffffff"})),
          "global styles rejects a stale version")
    persisted = assert_tool(client, editor_access, "get_global_styles")
    check(colors_in(persisted["settings"]["color"]["palette"]).get("secondary") == "#123abc"
          and persisted["user"]["styles"]["color"]["background"] == "#fefefe",
          "global styles changes persist across independent HTTP requests")
    global_styles_css_tests(client, admin_access, editor_access, selected_tokens["access_token"])

    templates = assert_tool(client, admin_access, "list_templates")
    template = next(item for item in templates["items"] if item["id"].endswith("//index"))
    template = assert_tool(client, admin_access, "get_template", {"id": template["id"]})
    check("Template fixture" in template["content"], "template tool reads the active theme's block template")
    updated_template = assert_tool(client, admin_access, "update_template", {
        "id": template["id"], "version": template["version"],
        "content": template["content"].replace("Template fixture", "Updated template fixture")})
    check("Updated template fixture" in updated_template["content"] and updated_template["version"] != template["version"],
          "administrator can save a versioned template database override")
    check(not tool_ok(tool(client, admin_access, "update_template", {
        "id": template["id"], "version": template["version"], "title": "Stale write"})),
          "template update rejects stale versions")
    check(not tool_ok(tool(client, editor_access, "update_template", {
        "id": template["id"], "version": updated_template["version"], "title": "Forbidden write"})),
          "editor cannot invoke a crafted template mutation")

    site_editing_tests(client, admin_access, editor_access, content_access, selected_tokens["access_token"])
    pattern_tests(client, editor, admin_access, editor_access, author_access, contributor_access, read_only_tokens["access_token"])

    settings = assert_tool(client, admin_access, "get_site_settings")
    check("title" in settings["settings"] and "admin_email" not in settings["settings"]
          and "url" not in settings["settings"], "site settings exposes an explicit non-sensitive allowlist")
    check(not tool_ok(tool(client, admin_access, "update_site_settings", {
        "version": settings["version"], "settings": {"admin_email": "attacker@example.test"}})),
          "site settings mutation rejects fields outside its allowlist")
    check(not tool_ok(tool(client, editor_access, "update_site_settings", {
        "version": settings["version"], "settings": {"title": "Forbidden title"}})),
          "editor cannot invoke a crafted site settings mutation")
    updated_settings = assert_tool(client, admin_access, "update_site_settings", {
        "version": settings["version"], "settings": {"description": "Updated by scoped MCP"}})
    check(updated_settings["settings"]["description"] == "Updated by scoped MCP"
          and updated_settings["settings"]["title"] == settings["settings"]["title"],
          "allowlisted site setting update preserves unrelated settings")
    check(not tool_ok(tool(client, admin_access, "update_site_settings", {
        "version": settings["version"], "settings": {"description": "Stale write"}})),
          "site settings rejects a stale version")
    settings_readonly, _ = grant(admin, registration, "settings:read")
    check("get_site_settings" in names_for(client, settings_readonly["access_token"])
          and not tool_ok(tool(client, settings_readonly["access_token"], "update_site_settings", {
              "version": updated_settings["version"], "settings": {"title": "No write scope"}})),
          "administrator read-only settings scope cannot write")

    plugins = assert_tool(client, admin_access, "list_plugins")
    check(any(item["id"] == "kodanote-mcp/kodanote-mcp" for item in plugins["items"]),
          "administrator can inspect installed plugin inventory")
    users = assert_tool(client, admin_access, "list_users")
    check(FIXTURES["users"]["admin"] in {item["id"] for item in users["items"]}
          and all("email" not in item and "user_pass" not in item for item in users["items"]),
          "administrator receives minimal user inventory without email or credentials")
    for name in ("list_plugins", "list_users", "get_site_settings"):
        check(not tool_ok(tool(client, editor_access, name)), "editor cannot invoke " + name)

    media = assert_tool(client, author_access, "get_media", {"id": FIXTURES["attachment"]})
    check(media["alt_text"] == "Original fixture alt text", "author can inspect their own media attachment")
    check(not tool_ok(tool(client, contributor_access, "get_media", {"id": FIXTURES["attachment"]})),
          "contributor cannot invoke a crafted media inspection")
    editor_media = assert_tool(client, editor_access, "get_media", {"id": FIXTURES["editor_attachment"]})
    check(not tool_ok(tool(client, author_access, "update_media", {
        "id": FIXTURES["editor_attachment"], "version": editor_media["version"], "alt_text": "Forbidden edit"})),
          "author cannot update another user's media attachment")
    changed_media = assert_tool(client, editor_access, "update_media", {
        "id": FIXTURES["attachment"], "version": media["version"], "alt_text": "Accessible fixture alt text"})
    check(changed_media["alt_text"] == "Accessible fixture alt text", "editor can improve another author's media metadata")
    check(not tool_ok(tool(client, author_access, "update_media", {
        "id": FIXTURES["attachment"], "version": media["version"], "alt_text": "Stale write"})),
          "media updates reject stale versions")
    check(not tool_ok(tool(client, author_access, "update_media", {
        "id": FIXTURES["attachment"], "version": changed_media["version"],
        "parent": FIXTURES["posts"]["contributor_draft"]})),
          "media update cannot attach to an inaccessible post")

    # Already-issued tokens must follow a role downgrade immediately, without reconnecting.
    try:
        set_fixture_role(FIXTURES["users"]["admin"], "editor")
        demoted_tools = names_for(client, admin_access)
        check(not privileged.intersection(demoted_tools) and "get_global_styles" in demoted_tools,
              "existing administrator token immediately loses tools after role downgrade")
        check(not tool_ok(tool(client, admin_access, "get_site_settings"))
              and not tool_ok(tool(client, admin_access, "update_global_styles", {
                  "version": persisted["version"], "text_color": "#ffffff"})),
              "role downgrade also blocks crafted calls with previously granted admin scopes")
    finally:
        set_fixture_role(FIXTURES["users"]["admin"], "administrator")
    routine_settings_tests(client, admin_access)
    audit_tests(client, admin, registration, admin_access, editor_access, read_only_tokens["access_token"])


def global_styles_css_tests(client, access, editor_access, readonly_access):
    definitions = rpc(client, access, "tools/list")[2]["result"]["tools"]
    definition = next(item for item in definitions if item["name"] == "update_global_styles")
    schema = definition["inputSchema"]["properties"].get("custom_css", {})
    check(set(schema.get("type", [])) == {"string", "null"}
          and schema.get("maxLength") == 50000
          and "custom_css" not in definition["inputSchema"].get("required", []),
          "CSS discovery exposes an optional string/null field bounded to 50000 characters")
    original = fixture_global_styles()["config"]
    css = ('.mcp-css-roundtrip::before { content: "Kodanote\'s \\"quoted\\" note"; '
           'margin-inline: calc(100% - 2rem); }\n'
           '@media (max-width: 640px) { .mcp-css-roundtrip { color: #123abc; } }')
    try:
        before = assert_tool(client, access, "get_global_styles")
        check(before.get("css_writable") is True
              and assert_tool(client, editor_access, "get_global_styles").get("css_writable") is False,
              "CSS reads distinguish administrator and editor writability")
        changed = assert_tool(client, access, "update_global_styles", {
            "version": before["version"], "custom_css": css})
        persisted = assert_tool(client, access, "get_global_styles")
        stored = fixture_global_styles()
        expected = json.loads(json.dumps(original))
        expected.setdefault("styles", {})["css"] = css
        check(persisted["user"]["styles"].get("css") == css and stored["config"] == expected,
              "CSS roundtrips quotes, apostrophes and media queries without changing unrelated configuration")
        check('.mcp-css-roundtrip::before' in stored["stylesheet"]
              and '@media (max-width: 640px)' in stored["stylesheet"]
              and 'calc(100% - 2rem)' in stored["stylesheet"]
              and 'Kodanote\'s \\"quoted\\" note' in stored["stylesheet"],
              "saved CSS appears in WordPress's actual generated custom stylesheet")
        check(not tool_ok(tool(client, access, "update_global_styles", {
            "version": before["version"], "custom_css": ".stale { color: red; }"}))
              and fixture_global_styles()["config"] == expected,
              "a stale CSS version cannot overwrite the saved stylesheet")

        omitted = assert_tool(client, access, "update_global_styles", {
            "version": persisted["version"], "background_color": "#102030"})
        check(fixture_global_styles()["config"]["styles"]["css"] == css,
              "an unrelated appearance edit preserves omitted CSS exactly")
        undo_change(client, access, omitted)
        check(fixture_global_styles()["config"] == expected,
              "undo of an unrelated appearance edit also preserves existing CSS")

        current = assert_tool(client, access, "get_global_styles")
        palette_reset = assert_tool(client, access, "update_global_styles", {
            "version": current["version"], "palette": []})
        palette_expected = json.loads(json.dumps(expected))
        del palette_expected["settings"]["color"]["palette"]
        if not palette_expected["settings"]["color"]:
            del palette_expected["settings"]["color"]
        check(fixture_global_styles()["config"] == palette_expected,
              "an explicit empty palette removes only the user palette while preserving CSS and typography")
        undo_change(client, access, palette_reset)
        check(fixture_global_styles()["config"] == expected,
              "palette-reset undo restores the exact prior palette and unrelated appearance configuration")

        invalid_values = [
            (42, "integer"), (False, "boolean"), ({"css": "body {}"}, "object"),
            ([], "array"), ("x" * 50001, "oversized string"),
            ('<style>.unsafe { color: red; }</style>', "style markup"),
            ('</style><script>alert("fixture")</script><style>', "closing-style injection"),
            ('.unsafe { color: red; }</sty', "partial closing-style markup"),
        ]
        for value, label in invalid_values:
            current = assert_tool(client, access, "get_global_styles")
            check(not tool_ok(tool(client, access, "update_global_styles", {
                "version": current["version"], "custom_css": value, "background_color": "#990000"})),
                  "CSS rejects " + label)
            check(fixture_global_styles()["config"] == expected
                  and assert_tool(client, access, "get_global_styles")["version"] == current["version"],
                  "rejected " + label + " leaves CSS, other supplied controls and version unchanged")

        boundary = "/*" + "é" * 49996 + "*/"
        current = assert_tool(client, access, "get_global_styles")
        bounded = assert_tool(client, access, "update_global_styles", {
            "version": current["version"], "custom_css": boundary})
        check(len(boundary) == 50000 and fixture_global_styles()["config"]["styles"]["css"] == boundary,
              "the CSS bound accepts exactly 50000 Unicode characters rather than counting bytes")
        undo_change(client, access, bounded)

        current = assert_tool(client, access, "get_global_styles")
        for denied_access, label in ((editor_access, "editor"), (readonly_access, "read-only appearance grant")):
            for value in (".denied { color: red; }", "", None):
                check(not tool_ok(tool(client, denied_access, "update_global_styles", {
                    "version": current["version"], "custom_css": value})),
                      label + " cannot write, empty or reset CSS")
        check(fixture_global_styles()["config"] == expected,
              "denied editor and scope-limited requests preserve all appearance data")

        entry = assert_tool(client, access, "get_audit_entry", {"id": changed["audit"]["id"]})
        check(entry["before"]["styles"] == original["styles"]
              and entry["after"]["styles"] == expected["styles"]
              and entry["before"]["settings"] == entry["after"]["settings"] == original["settings"],
              "CSS audit captures exact before/after styles and preserved settings")
        try:
            set_fixture_role(FIXTURES["users"]["admin"], "design_without_css")
            restricted = assert_tool(client, access, "get_global_styles")
            check(restricted.get("writable") is True and restricted.get("css_writable") is False,
                  "an appearance administrator without native CSS permission sees separate writability")
            for value in (".denied { color: red; }", "", None):
                check(not tool_ok(tool(client, access, "update_global_styles", {
                    "version": restricted["version"], "custom_css": value})),
                      "native CSS permission is required for replacement, emptying and reset")
            check(not tool_ok(tool(client, access, "update_global_styles", {
                "version": restricted["version"], "background_color": "#990000"})),
                  "missing CSS permission cannot strip existing root CSS through an unrelated edit")
            check(not tool_ok(tool(client, access, "revert_audit_entry", {
                "id": entry["id"], "version": entry["version"]})),
                  "an audit administrator losing CSS permission cannot undo a CSS mutation")
            check(fixture_global_styles()["config"] == expected,
                  "all missing-CSS-permission paths leave the complete configuration unchanged")
        finally:
            set_fixture_role(FIXTURES["users"]["admin"], "administrator")
        entry = assert_tool(client, access, "get_audit_entry", {"id": entry["id"]})
        assert_tool(client, access, "revert_audit_entry", {"id": entry["id"], "version": entry["version"]})
        check(fixture_global_styles()["config"]["styles"] == original["styles"]
              and fixture_global_styles()["config"]["settings"] == original["settings"],
              "eligible CSS undo restores the exact original styles and settings")
        reverted = assert_tool(client, access, "get_audit_entry", {"id": entry["id"]})
        check(not tool_ok(tool(client, access, "revert_audit_entry", {
            "id": reverted["id"], "version": reverted["version"]})), "CSS audit undo rejects replay")

        current = assert_tool(client, access, "get_global_styles")
        first = assert_tool(client, access, "update_global_styles", {"version": current["version"], "custom_css": css})
        first_entry = assert_tool(client, access, "get_audit_entry", {"id": first["audit"]["id"]})
        latest_css = ".mcp-newer-css { color: #334455; }"
        newer = assert_tool(client, access, "update_global_styles", {"version": first["version"], "custom_css": latest_css})
        check(not tool_ok(tool(client, access, "revert_audit_entry", {
            "id": first_entry["id"], "version": first_entry["version"]}))
              and fixture_global_styles()["config"]["styles"]["css"] == latest_css,
              "CSS undo detects intervening edits and preserves the newer stylesheet")
        empty = assert_tool(client, access, "update_global_styles", {"version": newer["version"], "custom_css": ""})
        check(fixture_global_styles()["config"]["styles"].get("css") == "",
              "empty-string CSS saves an explicit empty override")
        reset = assert_tool(client, access, "update_global_styles", {"version": empty["version"], "custom_css": None})
        reset_config = fixture_global_styles()["config"]
        check("css" not in reset_config["styles"]
              and reset_config["styles"] == original["styles"]
              and reset_config["settings"] == original["settings"],
              "null CSS removes only the user override and retains unrelated configuration")
        reset_entry = assert_tool(client, access, "get_audit_entry", {"id": reset["audit"]["id"]})
        try:
            set_fixture_role(FIXTURES["users"]["admin"], "design_without_css")
            check(not tool_ok(tool(client, access, "revert_audit_entry", {
                "id": reset_entry["id"], "version": reset_entry["version"]})),
                  "undo cannot restore even an empty CSS key after native CSS permission is lost")
            current = assert_tool(client, access, "get_global_styles")
            check(not tool_ok(tool(client, access, "update_global_styles", {
                "version": current["version"], "background_color": "#112244"}))
                  and fixture_global_styles()["config"] == reset_config,
                  "an ordinary edit rejects native filtering that would erase existing unrelated settings")
        finally:
            set_fixture_role(FIXTURES["users"]["admin"], "administrator")

        current = assert_tool(client, access, "get_global_styles")
        ordinary = assert_tool(client, access, "update_global_styles", {
            "version": current["version"], "background_color": "#112244"})
        ordinary_after = fixture_global_styles()["config"]
        ordinary_entry = assert_tool(client, access, "get_audit_entry", {"id": ordinary["audit"]["id"]})
        try:
            set_fixture_role(FIXTURES["users"]["admin"], "design_without_css")
            check(not tool_ok(tool(client, access, "revert_audit_entry", {
                "id": ordinary_entry["id"], "version": ordinary_entry["version"]}))
                  and fixture_global_styles()["config"] == ordinary_after,
                  "undo rejects native filtering of prior settings before causing a partial restore")
        finally:
            set_fixture_role(FIXTURES["users"]["admin"], "administrator")
        undo_change(client, access, ordinary)

        safe_config = json.loads(json.dumps(reset_config))
        safe_config.pop("settings", None)
        safe_before = fixture_global_styles(safe_config)["config"]
        try:
            set_fixture_role(FIXTURES["users"]["admin"], "design_without_css")
            current = assert_tool(client, access, "get_global_styles")
            palette_reset = assert_tool(client, access, "update_global_styles", {
                "version": current["version"], "palette": []})
            check(fixture_global_styles()["config"] == safe_before,
                  "a no-CSS appearance administrator can explicitly reset an already-empty palette without side effects")
            ordinary = assert_tool(client, access, "update_global_styles", {
                "version": palette_reset["version"], "palette": [], "background_color": "#112244"})
            check(fixture_global_styles()["config"]["styles"]["color"]["background"] == "#112244",
                  "a no-CSS appearance administrator can combine a palette reset with a native-safe background edit")
            undo_change(client, access, ordinary)
            check(fixture_global_styles()["config"] == safe_before,
                  "non-CSS appearance undo restores the exact native-safe configuration without CSS permission")
        finally:
            set_fixture_role(FIXTURES["users"]["admin"], "administrator")

        nested = json.loads(json.dumps(original))
        nested["styles"].setdefault("blocks", {})["core/paragraph"] = {"css": "& { color: #345678; }"}
        fixture_global_styles(nested)
        current = assert_tool(client, access, "get_global_styles")
        ordinary = assert_tool(client, access, "update_global_styles", {
            "version": current["version"], "background_color": "#123456"})
        nested_after = fixture_global_styles()["config"]
        nested_entry = assert_tool(client, access, "get_audit_entry", {"id": ordinary["audit"]["id"]})
        try:
            set_fixture_role(FIXTURES["users"]["admin"], "design_without_css")
            current = assert_tool(client, access, "get_global_styles")
            check(not tool_ok(tool(client, access, "update_global_styles", {
                "version": current["version"], "background_color": "#990000"})),
                  "omitted nested block CSS cannot be stripped by a caller without CSS permission")
            check(not tool_ok(tool(client, access, "revert_audit_entry", {
                "id": nested_entry["id"], "version": nested_entry["version"]})),
                  "audit undo of an ordinary edit still requires permission to preserve nested CSS")
            check(fixture_global_styles()["config"] == nested_after,
                  "nested CSS permission failures preserve the full saved configuration")
        finally:
            set_fixture_role(FIXTURES["users"]["admin"], "administrator")
    finally:
        set_fixture_role(FIXTURES["users"]["admin"], "administrator")
        fixture_global_styles(original)

    try:
        fixture_global_styles(theme="mcp-css-empty")
        blank = assert_tool(client, access, "get_global_styles")
        check(blank["user"]["id"] == 0 and fixture_global_styles()["id"] == 0,
              "fresh theme inspection does not create a user Global Styles record")
        check(not tool_ok(tool(client, access, "update_global_styles", {
            "version": blank["version"], "custom_css": '</style><script>alert("fixture")</script>',
            "background_color": "#990000"})),
              "native CSS validation rejects illegal markup on a theme without saved user styles")
        still_blank = assert_tool(client, access, "get_global_styles")
        check(fixture_global_styles()["id"] == 0 and still_blank["user"]["id"] == 0
              and still_blank["version"] == blank["version"],
              "invalid CSS is rejected before lazy record creation or a partial appearance write")
    finally:
        fixture_global_styles(theme="mcp-test")


def routine_settings_tests(client, access):
    original = assert_tool(client, access, "get_site_settings")
    check({"show_on_front", "page_on_front", "page_for_posts", "permalink_structure", "posts_per_rss",
           "thread_comments", "thumbnail_size_w"}.issubset(original["settings"]),
          "site settings expose reading, permalink, discussion and media controls")
    selected = assert_tool(client, access, "update_site_settings", {
        "version": original["version"], "settings": {
            "show_on_front": "page", "page_on_front": FIXTURES["posts"]["home"],
            "page_for_posts": FIXTURES["posts"]["blog"], "posts_per_rss": 7,
            "thread_comments": True, "thread_comments_depth": 3, "thumbnail_size_w": 240}})
    check(selected["settings"]["page_on_front"] == FIXTURES["posts"]["home"]
          and selected["settings"]["page_for_posts"] == FIXTURES["posts"]["blog"]
          and selected["settings"]["thumbnail_size_w"] == 240,
          "homepage, blog, discussion and image-size settings persist together")
    for invalid, label in (
        ({"page_on_front": FIXTURES["posts"]["draft_page"]}, "unpublished homepage"),
        ({"page_for_posts": FIXTURES["posts"]["home"]}, "identical homepage and blog page"),
        ({"page_on_front": FIXTURES["posts"]["public"]}, "post used as homepage"),
        ({"permalink_structure": ""}, "plain permalinks that change the OAuth resource"),
        ({"permalink_structure": "/wp-admin/%postname%/"}, "reserved custom permalink path"),
        ({"siteurl": "https://attacker.example"}, "site URL"),
        ({"users_can_register": True}, "user registration"),
        ({"default_role": "administrator"}, "default role"),
        ({"active_plugins": []}, "plugin activation option"),
        ({"thread_comments_depth": 100}, "excessive nesting"),
    ):
        check(not tool_ok(tool(client, access, "update_site_settings", {
            "version": selected["version"], "settings": dict(invalid, description="Must not partially save")})),
            "settings preflight rejects " + label)
    after_invalid = assert_tool(client, access, "get_site_settings")
    check(after_invalid["version"] == selected["version"], "rejected settings batches leave all settings unchanged")
    changed = assert_tool(client, access, "update_site_settings", {
        "version": after_invalid["version"], "settings": {"permalink_structure": "/%year%/%monthnum%/%postname%/"}})
    check(changed["settings"]["permalink_structure"] == "/%year%/%monthnum%/%postname%/"
          and tool_ok(tool(client, access, "get_site_info")),
          "safe pretty permalink change preserves the authorized MCP endpoint")
    check(client.request(BASE + "/.well-known/oauth-protected-resource")[0] == 200
          and client.request(BASE + "/wp-login.php")[0] == 200,
          "permalink update keeps OAuth discovery and WordPress login reachable")
    # Restore only the settings changed above through the same public tool.
    keys = ["show_on_front", "page_on_front", "page_for_posts", "posts_per_rss", "thread_comments",
            "thread_comments_depth", "thumbnail_size_w", "permalink_structure"]
    restored = assert_tool(client, access, "update_site_settings", {
        "version": changed["version"], "settings": {key: original["settings"][key] for key in keys}})
    check(all(restored["settings"][key] == original["settings"][key] for key in keys),
          "routine settings can be restored through validated normal controls")


def audit_tests(client, admin, registration, access, editor_access, readonly_access):
    before = assert_tool(client, access, "get_site_settings")
    try:
        fixture_fault("audit_insert")
        check(not tool_ok(tool(client, access, "update_site_settings", {
            "version": before["version"], "settings": {"description": "Unaudited change must not persist"}})),
              "mutation fails closed when the pending audit entry cannot be persisted")
    finally:
        fixture_fault("")
    unchanged = assert_tool(client, access, "get_site_settings")
    check(unchanged["settings"] == before["settings"], "audit-store failure leaves target settings unchanged")
    edited = assert_tool(client, access, "update_site_settings", {
        "version": before["version"], "settings": {"description": "Audited settings change"}})
    entry_id = edited["audit"]["id"]
    check(edited["audit"]["reversible"], "settings mutation returns a reversible audit reference")
    entry = assert_tool(client, access, "get_audit_entry", {"id": entry_id})
    check(entry["tool"] == "update_site_settings" and entry["status"] == "success"
          and entry["user_id"] == FIXTURES["users"]["admin"]
          and entry["client_id"] == registration["client_id"]
          and "before" in entry and "after" in entry,
          "audit records authenticated actor, client, outcome and before/after state")
    status, _, history_html = admin.request(BASE + "/wp-admin/tools.php?page=kodanote-mcp-audit")
    check(status == 200 and "MCP Audit Log" in history_html and "update_site_settings" in history_html,
          "WordPress administrators can inspect audit history without an MCP client")
    status, _, entry_html = admin.request(BASE + "/wp-admin/tools.php?page=kodanote-mcp-audit&entry=" + str(entry_id))
    check(status == 200 and "Audited settings change" in entry_html, "WordPress audit detail displays before/after snapshots")
    check(access not in json.dumps(entry) and "integration-only-password" not in json.dumps(entry)
          and "refresh_token" not in json.dumps(entry), "audit record excludes authentication credentials")
    log = assert_tool(client, access, "list_audit_log", {
        "tool": "update_site_settings", "target": "site:settings", "status": "success",
        "user_id": FIXTURES["users"]["admin"], "per_page": 1})
    check(len(log["items"]) == 1 and log["items"][0]["id"] == entry_id
          and "before" not in log["items"][0], "audit filters and pagination return bounded metadata without snapshots")
    empty = assert_tool(client, access, "list_audit_log", {"after": "2100-01-01T00:00:00Z"})
    check(empty["items"] == [], "audit date filter excludes older operations")
    for denied_access, role in ((editor_access, "editor"), (readonly_access, "read-only OAuth connection")):
        check(not tool_ok(tool(client, denied_access, "revert_audit_entry", {"id": entry_id, "version": entry["version"]})),
              role + " cannot invoke audit undo")
    check(not tool_ok(tool(client, editor_access, "get_audit_entry", {"id": entry_id})),
          "editor cannot retrieve private audit snapshots")
    audit_only, _ = grant(admin, registration, "audit:write")
    check(not tool_ok(tool(client, audit_only["access_token"], "revert_audit_entry", {"id": entry_id, "version": entry["version"]})),
          "audit write scope alone cannot restore settings without original settings write scope")
    check(not tool_ok(tool(client, access, "revert_audit_entry", {"id": entry_id, "version": "0" * 64})),
          "undo rejects a stale audit entry version")
    undone = assert_tool(client, access, "revert_audit_entry", {"id": entry_id, "version": entry["version"]})
    current = assert_tool(client, access, "get_site_settings")
    check(current["settings"]["description"] == before["settings"]["description"],
          "audit undo restores the original setting")
    after_undo = assert_tool(client, access, "get_audit_entry", {"id": entry_id})
    check(after_undo["status"] == "reverted" and after_undo["reverted_by_entry_id"],
          "undo records a linked audit event and marks the original entry reverted")
    undo_entry = assert_tool(client, access, "get_audit_entry", {"id": after_undo["reverted_by_entry_id"]})
    check(undo_entry["before"]["state"]["description"] == "Audited settings change"
          and undo_entry["after"]["state"]["description"] == before["settings"]["description"]
          and not undo_entry["reversible"], "undo event records its own actual before/after state without allowing undo chains")
    check(not tool_ok(tool(client, access, "revert_audit_entry", {"id": entry_id, "version": after_undo["version"]})),
          "a successfully reverted entry cannot be undone again")

    first = assert_tool(client, access, "update_site_settings", {
        "version": current["version"], "settings": {"description": "First audit edit"}})
    first_entry = assert_tool(client, access, "get_audit_entry", {"id": first["audit"]["id"]})
    newer = assert_tool(client, access, "update_site_settings", {
        "version": first["version"], "settings": {"description": "Newer human or agent edit"}})
    check(not tool_ok(tool(client, access, "revert_audit_entry", {"id": first_entry["id"], "version": first_entry["version"]})),
          "undo refuses to overwrite a newer change to the affected resource")
    still_new = assert_tool(client, access, "get_site_settings")
    check(still_new["settings"]["description"] == "Newer human or agent edit",
          "conflicted undo preserves the newer setting")
    race = assert_tool(client, access, "update_site_settings", {
        "version": still_new["version"], "settings": {"description": "Undo race fixture"}})
    race_entry = assert_tool(client, access, "get_audit_entry", {"id": race["audit"]["id"]})
    try:
        fixture_fault("audit_race_settings")
        check(not tool_ok(tool(client, access, "revert_audit_entry", {"id": race_entry["id"], "version": race_entry["version"]})),
              "undo rejects a native edit injected between its drift check and restoration read")
    finally:
        fixture_fault("")
    still_new = assert_tool(client, access, "get_site_settings")
    check(still_new["settings"]["description"] == "Concurrent native edit during undo",
          "undo never blesses a newer state by reading a fresh version after its drift check")
    try:
        fixture_fault("settings_partial")
        check(not tool_ok(tool(client, access, "update_site_settings", {
            "version": still_new["version"], "settings": {"description": "Partially applied settings fixture", "thumbnail_size_w": 999}})),
              "a plugin rejecting one setting produces an explicit partial-write error")
    finally:
        fixture_fault("")
    partials = assert_tool(client, access, "list_audit_log", {"tool": "update_site_settings", "status": "partial", "per_page": 1})
    check(partials["items"] and not partials["items"][0]["reversible"],
          "partial writes are identified in the audit log and excluded from automatic undo")
    partial = assert_tool(client, access, "get_audit_entry", {"id": partials["items"][0]["id"]})
    check(partial["before"]["description"] == "Concurrent native edit during undo"
          and partial["after"]["description"] == "Partially applied settings fixture",
          "partial audit entry captures the actual changed state for manual recovery")
    still_new = assert_tool(client, access, "get_site_settings")
    failed = tool(client, access, "update_site_settings", {
        "version": still_new["version"], "settings": {"timezone": "Invalid/Timezone"}})
    check(not tool_ok(failed), "invalid mutation reports failure")
    failures = assert_tool(client, access, "list_audit_log", {"tool": "update_site_settings", "status": "failed", "per_page": 1})
    check(failures["items"] and not failures["items"][0]["reversible"], "failed mutations are logged and cannot be reverted")
    created = assert_tool(client, access, "create_content", {"title": "Audited draft creation"})
    created_entry = assert_tool(client, access, "get_audit_entry", {"id": created["audit"]["id"]})
    check(not created_entry["reversible"] and created_entry.get("revert_reason"),
          "creation is logged with an explicit nonreversible reason instead of deleting it during undo")

    # Exercise each resource adapter against a real write and a read after undo.
    content = assert_tool(client, access, "get_content", {"id": created["id"]})
    changed = assert_tool(client, access, "update_content", {"id": created["id"], "title": "Audited content edit"})
    undo_change(client, access, changed)
    check(assert_tool(client, access, "get_content", {"id": created["id"]})["title"] == content["title"],
          "content undo restores saved fields")
    comment = fixture_comment(created["id"])
    trashed = assert_tool(client, access, "trash_content", {"id": created["id"]})
    trash_entry = assert_tool(client, access, "get_audit_entry", {"id": trashed["audit"]["id"]})
    fixture_comment(created["id"], comment["id"], "spam")
    check(not tool_ok(tool(client, access, "revert_audit_entry", {"id": trash_entry["id"], "version": trash_entry["version"]})),
          "trash undo detects an intervening moderator change to a related comment")
    check(assert_tool(client, access, "get_content", {"id": created["id"]})["status"] == "trash"
          and fixture_comment(created["id"], comment["id"], "__read")["status"] == "spam",
          "moderation conflict leaves the post in trash without running native comment restoration")
    fixture_comment(created["id"], comment["id"], "post-trashed")
    undo_change(client, access, trashed)
    check(assert_tool(client, access, "get_content", {"id": created["id"]})["status"] == "draft"
          and fixture_comment(created["id"], comment["id"], "__read")["status"] == "1",
          "trash undo restores the previous post and comment statuses without permanent deletion")
    media = assert_tool(client, access, "get_media", {"id": FIXTURES["attachment"]})
    changed = assert_tool(client, access, "update_media", {"id": media["id"], "version": media["version"], "alt_text": "Audit media edit"})
    undo_change(client, access, changed)
    check(assert_tool(client, access, "get_media", {"id": media["id"]})["alt_text"] == media["alt_text"],
          "media undo restores metadata without replacing the file")
    menu = assert_tool(client, access, "get_navigation", {"id": FIXTURES["navigation"]})
    changed = assert_tool(client, access, "update_navigation", {"id": menu["id"], "version": menu["version"], "title": "Audit menu edit"})
    menu_entry = assert_tool(client, access, "get_audit_entry", {"id": changed["audit"]["id"]})
    try:
        set_fixture_role(FIXTURES["users"]["admin"], "audit_manager")
        check(tool_ok(tool(client, access, "get_audit_entry", {"id": menu_entry["id"]}))
              and not tool_ok(tool(client, access, "revert_audit_entry", {"id": menu_entry["id"], "version": menu_entry["version"]})),
              "an audit administrator losing theme permissions can inspect history but cannot restore navigation")
    finally:
        set_fixture_role(FIXTURES["users"]["admin"], "administrator")
    undo_change(client, access, changed)
    check(assert_tool(client, access, "get_navigation", {"id": menu["id"]})["title"] == menu["title"],
          "navigation undo restores saved menu fields")
    styles = assert_tool(client, access, "get_global_styles")
    changed = assert_tool(client, access, "update_global_styles", {"version": styles["version"], "background_color": "#eeccaa"})
    undo_change(client, access, changed)
    styles_after = assert_tool(client, access, "get_global_styles")
    check(styles_after["user"]["styles"] == styles["user"]["styles"]
          and styles_after["user"]["settings"] == styles["user"]["settings"],
          "global style undo restores user overrides and preserves unrelated theme settings")
    target = {"id": "mcp-test//footer", "type": "template_part"}
    footer = assert_tool(client, access, "get_template", target)
    changed = assert_tool(client, access, "update_template", dict(target, version=footer["version"],
        content=footer["content"] + "<!-- wp:paragraph --><p>Audit template edit</p><!-- /wp:paragraph -->"))
    undo_change(client, access, changed)
    check(assert_tool(client, access, "get_template", target)["content"] == footer["content"],
          "template undo restores exact raw markup including pattern references")
    layout = assert_tool(client, access, "get_layout", target)
    first_block = next(block for block in layout["blocks"] if block["name"])
    changed = assert_tool(client, access, "update_layout", dict(target, version=layout["version"], operations=[
        {"action": "insert_after", "path": first_block["path"], "content": "<!-- wp:paragraph --><p>Audit layout edit</p><!-- /wp:paragraph -->"}]))
    undo_change(client, access, changed)
    check(assert_tool(client, access, "get_layout", target)["content"] == layout["content"],
          "targeted layout undo restores the original template structure")


def pattern_tests(client, editor, admin_access, editor_access, author_access, contributor_access, readonly_access):
    paragraph = "<!-- wp:paragraph --><p>%s</p><!-- /wp:paragraph -->"
    group = '<!-- wp:group --><div class="wp-block-group">%s</div><!-- /wp:group -->'
    editor_tools = names_for(client, editor_access)
    contributor_tools = names_for(client, contributor_access)
    readonly_tools = names_for(client, readonly_access)
    check({"list_patterns", "get_pattern", "create_pattern", "update_pattern"}.issubset(editor_tools),
          "editor discovers reusable pattern tools")
    check({"list_patterns", "get_pattern", "update_pattern"}.issubset(contributor_tools) and "create_pattern" not in contributor_tools,
          "contributor discovers pattern reads but not creation, which requires publish permission")
    check({"list_patterns", "get_pattern"}.issubset(readonly_tools)
          and not readonly_tools.intersection({"create_pattern", "update_pattern"}),
          "read-only content grant discovers only pattern reads")
    check(not tool_ok(tool(client, contributor_access, "create_pattern", {"title": "Forbidden pattern", "content": paragraph % "No"})),
          "contributor cannot invoke a crafted pattern creation")
    check({"list_block_patterns", "get_block_pattern"}.issubset(contributor_tools)
          and {"list_block_patterns", "get_block_pattern"}.issubset(readonly_tools),
          "anyone who writes content, and read-only grants, can browse ready-made designs")
    everything = assert_tool(client, editor_access, "list_block_patterns", {"per_page": 100})
    check(everything["total"] >= 1 and all("content" not in item for item in everything["items"])
          and isinstance(everything["available_categories"], dict),
          "block pattern listing returns registered designs and categories without their markup")
    found = assert_tool(client, contributor_access, "list_block_patterns", {"search": "PRESERVED footer"})
    check([item["name"] for item in found["items"]] == ["mcp-test/preserved-footer"]
          and found["items"][0]["title"] == "Preserved footer fixture",
          "block pattern search matches names and titles case-insensitively")
    design = assert_tool(client, contributor_access, "get_block_pattern", {"name": "mcp-test/preserved-footer"})
    check("Resolved footer pattern fixture" in design["content"], "block pattern read returns markup to copy and adapt")
    check(not tool_ok(tool(client, contributor_access, "get_block_pattern", {"name": "mcp-test/missing"})),
          "unknown block pattern names fail cleanly")

    cta = assert_tool(client, editor_access, "create_pattern", {
        "title": "Call to action", "content": paragraph % "Shared call to action v1", "categories": ["Calls to action"]})
    check(cta["sync_status"] == "synced" and cta["status"] == "publish" and cta["categories"] == ["Calls to action"]
          and cta["insert_markup"] == '<!-- wp:block {"ref":%d} /-->' % cta["id"] and cta["editable"] is True
          and cta["usage"] == {"total": 0, "items": [], "hidden": 0, "truncated": False}
          and cta["audit"]["status"] == "success" and cta["audit"]["reversible"] is False,
          "synced pattern creation publishes, creates its category, is audited and starts unused")
    page = assert_tool(client, editor_access, "create_content", {
        "post_type": "page", "title": "Pattern host page", "status": "publish", "content": group % cta["insert_markup"]})
    draft = assert_tool(client, contributor_access, "create_content", {
        "title": "Contributor pattern draft", "content": cta["insert_markup"]})
    usage = assert_tool(client, editor_access, "get_pattern", {"id": cta["id"]})["usage"]
    check(usage["total"] == 2 and usage["hidden"] == 0 and {item["id"] for item in usage["items"]} == {page["id"], draft["id"]},
          "pattern usage finds nested and draft references the editor may open")
    host = next(item for item in usage["items"] if item["id"] == page["id"])
    check(host["type"] == "page" and host["type_label"] == "Page" and host.get("link") and host.get("edit_link"),
          "usage items identify embedding content with view and edit links")

    author_view = assert_tool(client, author_access, "get_pattern", {"id": cta["id"]})
    check(author_view["editable"] is False and author_view["insert_markup"] == cta["insert_markup"]
          and author_view["usage"]["total"] == 2 and author_view["usage"]["hidden"] == 1
          and [item["id"] for item in author_view["usage"]["items"]] == [page["id"]]
          and "Contributor pattern draft" not in json.dumps(author_view),
          "author can read another user's published pattern to embed it, and only counts drafts they cannot open")
    check(not tool_ok(tool(client, author_access, "update_pattern", {
        "id": cta["id"], "version": author_view["version"], "title": "Hijacked"})),
          "author cannot update another user's pattern")

    check(not tool_ok(tool(client, editor_access, "update_pattern", {"id": cta["id"], "version": "0" * 64, "title": "Stale"})),
          "pattern update rejects a stale version")
    check(not tool_ok(tool(client, editor_access, "update_pattern", {
        "id": cta["id"], "version": cta["version"], "content": group % cta["insert_markup"]})),
          "pattern update rejects a pattern embedding itself")
    updated = assert_tool(client, editor_access, "update_pattern", {
        "id": cta["id"], "version": cta["version"], "content": paragraph % "Shared call to action v2"})
    check("v2" in updated["content"] and updated["version"] != cta["version"]
          and updated["usage"]["total"] == 2 and updated["audit"]["reversible"],
          "pattern update saves, reports its reach and is reversible")
    rendered_url = BASE + "/wp-json/wp/v2/pages/%d" % page["id"]
    status, _, body = client.request(rendered_url)
    check(status == 200 and "Shared call to action v2" in body["content"]["rendered"],
          "the published page renders the edited synced pattern")
    check(not tool_ok(tool(client, editor_access, "update_pattern", {
        "id": cta["id"], "version": cta["version"], "title": "Old version"})),
          "a version read before an update is stale afterwards")
    undo_change(client, admin_access, updated)
    restored = assert_tool(client, editor_access, "get_pattern", {"id": cta["id"]})
    status, _, body = client.request(rendered_url)
    check(restored["content"] == paragraph % "Shared call to action v1" and "Shared call to action v1" in body["content"]["rendered"],
          "audit undo restores the pattern and every page embedding it")

    starter = assert_tool(client, editor_access, "create_pattern", {
        "title": "Starter layout", "sync_status": "unsynced",
        "content": '<!-- wp:heading --><h2 class="wp-block-heading">Starter</h2><!-- /wp:heading -->'})
    check(starter["sync_status"] == "unsynced" and starter["insert_markup"] == "",
          "unsynced patterns are created as copy-on-insert starters")
    synced = {item["id"] for item in assert_tool(client, editor_access, "list_patterns", {"sync_status": "synced", "per_page": 50})["items"]}
    unsynced = {item["id"] for item in assert_tool(client, editor_access, "list_patterns", {"sync_status": "unsynced", "per_page": 50})["items"]}
    check(cta["id"] in synced and starter["id"] not in synced and starter["id"] in unsynced and cta["id"] not in unsynced,
          "pattern listing filters by sync status")
    listed = assert_tool(client, editor_access, "list_patterns", {"category": "Calls to action", "include_usage": True})
    check([item["id"] for item in listed["items"]] == [cta["id"]] and listed["items"][0]["usage_count"] == 2,
          "pattern listing filters by category name and can include usage counts")
    starter = assert_tool(client, editor_access, "update_pattern", {
        "id": starter["id"], "version": starter["version"], "categories": ["Calls to action", "Starters"]})
    check(starter["categories"] == ["Calls to action", "Starters"] and starter["sync_status"] == "unsynced",
          "pattern categories are replaced by name, creating missing ones")
    check(not tool_ok(tool(client, author_access, "create_pattern", {
        "title": "Author categorized", "content": paragraph % "x", "categories": ["Author invented category"]})),
          "author cannot create new pattern categories")
    own = assert_tool(client, author_access, "create_pattern", {
        "title": "Author pattern", "content": paragraph % "Author shared text", "categories": ["Starters"]})
    check(own["editable"] is True and own["categories"] == ["Starters"], "author can create a pattern in an existing category")
    author_list = {item["id"]: item for item in assert_tool(client, author_access, "list_patterns", {"per_page": 50})["items"]}
    check(own["id"] in author_list and cta["id"] in author_list and author_list[cta["id"]]["editable"] is False,
          "author listing includes shared published patterns, marked read-only")

    status, _, html = editor.request(BASE + "/wp-admin/edit.php?post_type=wp_block")
    check(status == 200 and "Used in" in html and "Pattern host page" in html and "Contributor pattern draft" in html
          and "Not synced. Inserted copies are not tracked." in html,
          "WordPress pattern list shows where each pattern is used")
    status, _, nonce = editor.request(BASE + "/wp-admin/admin-ajax.php?action=rest-nonce")
    nonce = str(nonce).strip()
    check(status == 200 and re.fullmatch(r"[0-9a-f]{10}", nonce), "logged-in editor receives a REST nonce")
    usage_url = API + "/patterns/%d/usage" % cta["id"]
    status, _, body = editor.request(usage_url, headers={"X-WP-Nonce": nonce})
    check(status == 200 and body.get("synced") is True and body.get("total") == 2
          and page["id"] in {item["id"] for item in body.get("items", [])},
          "editor panel route reports usage for a cookie-authenticated editor")
    check(editor.request(usage_url)[0] in (401, 403) and client.request(usage_url)[0] in (401, 403),
          "pattern usage route requires a logged-in user and a REST nonce")
    status, _, html = editor.request(BASE + "/wp-admin/post.php?post=%d&action=edit" % cta["id"])
    check(status == 200 and "kodanote-mcp/assets/pattern-usage.js" in html, "pattern editor loads the Used in panel")
    status, _, html = editor.request(BASE + "/wp-admin/post.php?post=%d&action=edit" % page["id"])
    check(status == 200 and "pattern-usage.js" not in html, "ordinary page editing does not load the pattern panel")


def undo_change(client, access, changed):
    check(changed["audit"]["reversible"], "supported update exposes reversible audit metadata")
    entry = assert_tool(client, access, "get_audit_entry", {"id": changed["audit"]["id"]})
    return assert_tool(client, access, "revert_audit_entry", {"id": entry["id"], "version": entry["version"]})


def site_editing_tests(client, admin_access, editor_access, content_access, readonly_access):
    footer_parts = assert_tool(client, admin_access, "list_templates", {"type": "template_part", "area": "footer"})
    header_parts = assert_tool(client, admin_access, "list_templates", {"type": "template_part", "area": "header"})
    check(footer_parts["items"] and all(item["area"] == "footer" for item in footer_parts["items"])
          and header_parts["items"] and all(item["area"] == "header" for item in header_parts["items"]),
          "template discovery filters header and footer areas independently")
    footer_id = next(item["id"] for item in footer_parts["items"] if item["slug"] == "footer")
    footer = assert_tool(client, admin_access, "get_template", {"type": "template_part", "id": footer_id})
    check(footer["content"] == FIXTURES["footer_content"] and "<strong>bold unchanged</strong>" in footer["content"],
          "footer discovery returns original nested theme markup")
    check('<!-- wp:pattern {"slug":"mcp-test/preserved-footer"} /-->' in footer["content"]
          and "Resolved footer pattern fixture" not in footer["content"]
          and "Resolved footer pattern fixture" in footer["resolved_content"],
          "template reads keep saved pattern references separate from resolved display content")
    footer = assert_tool(client, admin_access, "update_template", {
        "type": "template_part", "id": footer_id, "version": footer["version"],
        "content": footer["content"].replace("Footer fixture", "Updated footer fixture")})
    stored = fixture_storage(footer["wp_id"])
    check(stored["post_type"] == "wp_template_part" and stored["post_content"] == footer["content"]
          and stored["footer_file"] == FIXTURES["footer_content"],
          "footer update persists a database override while leaving the theme file unchanged")
    reread = assert_tool(client, admin_access, "get_template", {"type": "template_part", "id": footer_id})
    check(reread["content"] == footer["content"], "footer database override survives another HTTP request")
    layout_editing_tests(client, admin_access, editor_access, content_access, readonly_access, footer_id)
    footer = assert_tool(client, admin_access, "get_template", {"type": "template_part", "id": footer_id})
    check(not tool_ok(tool(client, admin_access, "create_template", {
        "type": "template_part", "slug": "footer", "area": "footer", "title": "Duplicate footer",
        "content": "<!-- wp:paragraph --><p>Should never overwrite</p><!-- /wp:paragraph -->"})),
          "template creation refuses to overwrite an existing theme or database template")
    still_footer = assert_tool(client, admin_access, "get_template", {"type": "template_part", "id": footer_id})
    check(still_footer["version"] == footer["version"] and still_footer["content"] == footer["content"],
          "failed duplicate template creation leaves the original footer unchanged")
    new_footer = assert_tool(client, admin_access, "create_template", {
        "type": "template_part", "slug": "campaign-footer", "area": "footer", "title": "Campaign footer",
        "content": "<!-- wp:paragraph --><p>Campaign footer fixture</p><!-- /wp:paragraph -->"})
    check(new_footer["slug"] == "campaign-footer" and new_footer["area"] == "footer",
          "administrator can create a reusable footer part with its area")
    searched = assert_tool(client, admin_access, "list_templates", {
        "type": "template_part", "area": "footer", "search": "campaign"})
    check(len(searched["items"]) == 1 and searched["items"][0]["id"] == new_footer["id"],
          "template discovery combines area and search filters")
    check(not tool_ok(tool(client, admin_access, "create_template", {
        "slug": "illegal-area", "area": "footer", "title": "Invalid area", "content": "<!-- wp:paragraph --><p>Invalid</p><!-- /wp:paragraph -->"})),
          "ordinary template creation rejects a template-part-only area")
    for access, role in ((editor_access, "editor"), (readonly_access, "read-only appearance token")):
        check(not tool_ok(tool(client, access, "create_template", {
            "type": "template_part", "slug": "forbidden-footer", "area": "footer", "title": "Forbidden footer",
            "content": "<!-- wp:paragraph --><p>Forbidden</p><!-- /wp:paragraph -->"})),
              role + " cannot create footer template parts")

    styles = assert_tool(client, admin_access, "get_global_styles")
    sized = assert_tool(client, admin_access, "update_global_styles", {
        "version": styles["version"], "content_width": "720px", "wide_width": "1280px",
        "block_gap": "1.5rem", "padding": {"top": "2rem", "right": "3vw", "bottom": "2rem", "left": "3vw"}})
    check(sized["user"]["settings"]["layout"] == {"contentSize": "720px", "wideSize": "1280px"}
          and sized["user"]["styles"]["spacing"]["blockGap"] == "1.5rem"
          and sized["user"]["styles"]["spacing"]["padding"]["left"] == "3vw",
          "global layout controls save width, block gap, and side-specific padding")
    check(sized["user"]["styles"]["color"] == styles["user"]["styles"]["color"]
          and sized["user"]["styles"]["typography"] == styles["user"]["styles"]["typography"],
          "global layout edits preserve existing color and typography overrides")
    for field, value in (("content_width", "url(https://attacker.test/)"), ("wide_width", "-12px"),
                         ("block_gap", "100001px"), ("padding", {"top": "1px;display:none"})):
        check(not tool_ok(tool(client, admin_access, "update_global_styles", {
            "version": sized["version"], field: value})), "global layout rejects invalid " + field)
    reset = assert_tool(client, admin_access, "update_global_styles", {
        "version": sized["version"], "content_width": None, "padding": {"left": None}})
    check("contentSize" not in reset["user"]["settings"]["layout"]
          and reset["user"]["settings"]["layout"]["wideSize"] == "1280px"
          and "left" not in reset["user"]["styles"]["spacing"]["padding"]
          and reset["user"]["styles"]["spacing"]["padding"]["top"] == "2rem",
          "null resets individual layout overrides while preserving other values")
    check(reset["settings"]["layout"]["contentSize"] == "680px",
          "reset layout width inherits the active theme value")

    navigation = assert_tool(client, admin_access, "list_navigation", {"search": "Fixture primary"})
    check(FIXTURES["navigation"] in {item["id"] for item in navigation["items"]},
          "administrator discovers the reusable navigation linked by the header")
    menu = assert_tool(client, admin_access, "get_navigation", {"id": FIXTURES["navigation"]})
    check('"label":"More"' in menu["content"] and '"url":"/about/"' in menu["content"],
          "navigation read includes nested submenu link markup")
    updated_menu = assert_tool(client, admin_access, "update_navigation", {
        "id": menu["id"], "version": menu["version"],
        "content": menu["content"].replace('"label":"About","url":"/about/"', '"label":"Our team","url":"/team/"')})
    persisted_menu = assert_tool(client, admin_access, "get_navigation", {"id": menu["id"]})
    stored_menu = fixture_storage(menu["id"])
    check('"label":"Our team"' in persisted_menu["content"] and '"url":"/team/"' in persisted_menu["content"]
          and '"label":"More"' in persisted_menu["content"]
          and stored_menu["post_content"] == persisted_menu["content"]
          and stored_menu["header_file"] == FIXTURES["header_content"],
          "nested navigation link edit persists independently without changing its header reference")
    check(not tool_ok(tool(client, admin_access, "update_navigation", {
        "id": menu["id"], "version": menu["version"], "title": "Stale menu"})),
          "navigation update rejects stale versions")
    check(not tool_ok(tool(client, admin_access, "update_navigation", {
        "id": menu["id"], "version": updated_menu["version"], "content": "<?php echo 'not allowed'; ?>"})),
          "navigation update rejects executable PHP")
    check(not tool_ok(tool(client, admin_access, "update_navigation", {
        "id": menu["id"], "version": updated_menu["version"],
        "content": "<!-- wp:shortcode -->[unsafe_shortcode]<!-- /wp:shortcode -->"})),
          "navigation update rejects unrelated shortcode blocks")
    for markup, label in (("<!-- wp:navigation-submenu -->", "unclosed submenus"),
                          ('<!-- wp:navigation-link {"label":} /-->', "malformed attribute JSON"),
                          ('<!-- wp:navigation-link {"label":42,"url":"/"} /-->', "incorrect native attribute types"),
                          ('<!-- wp:navigation-link {"label":"Item","url":"/"} /-->' * 251, "more than 250 blocks")):
        check(not tool_ok(tool(client, admin_access, "update_navigation", {
            "id": menu["id"], "version": updated_menu["version"], "content": markup})),
              "navigation validation rejects " + label)
    unchanged_menu = assert_tool(client, admin_access, "get_navigation", {"id": menu["id"]})
    check(unchanged_menu["version"] == updated_menu["version"] and unchanged_menu["content"] == updated_menu["content"],
          "failed navigation validation leaves the saved submenu unchanged")
    created_menu = assert_tool(client, admin_access, "create_navigation", {
        "title": "Campaign navigation", "content": '<!-- wp:navigation-link {"label":"Campaign","url":"/campaign/"} /-->'})
    check(created_menu["id"] != menu["id"] and '"ref":' + str(created_menu["id"]) in created_menu["navigation_block"]
          and created_menu["status"] == "draft", "new reusable navigation defaults to draft and returns a block reference")
    nav_layout = assert_tool(client, admin_access, "get_layout", {"id": footer_id, "type": "template_part"})
    nav_insert_path = next(block["path"] for block in walk_layout(nav_layout["blocks"])
                           if block["name"] == "core/paragraph")
    attach_navigation = [{"action": "insert_after", "path": nav_insert_path, "content": created_menu["navigation_block"]}]
    check(not tool_ok(tool(client, admin_access, "update_layout", {
        "id": footer_id, "type": "template_part", "version": nav_layout["version"], "operations": attach_navigation})),
          "layout editing rejects attaching an unpublished navigation menu")
    after_draft = assert_tool(client, admin_access, "get_layout", {"id": footer_id, "type": "template_part"})
    check(after_draft["version"] == nav_layout["version"] and after_draft["content"] == nav_layout["content"],
          "rejected draft navigation attachment leaves the saved footer unchanged")
    published_menu = assert_tool(client, admin_access, "update_navigation", {
        "id": created_menu["id"], "version": created_menu["version"], "status": "publish"})
    check(published_menu["status"] == "publish" and published_menu["content"] == created_menu["content"],
          "navigation publishing is explicit and preserves menu content")
    attached_layout = assert_tool(client, admin_access, "update_layout", {
        "id": footer_id, "type": "template_part", "version": after_draft["version"], "operations": attach_navigation})
    check(any(block["name"] == "core/navigation" and block["attributes"].get("ref") == created_menu["id"]
              for block in walk_layout(attached_layout["blocks"])),
          "the same navigation reference can be attached after explicit publication")
    for access, role in ((editor_access, "editor"), (content_access, "content-only token")):
        check(not tool_ok(tool(client, access, "get_navigation", {"id": menu["id"]})),
              role + " cannot read privileged navigation content")
    for access, role in ((editor_access, "editor"), (readonly_access, "read-only appearance token")):
        check(not tool_ok(tool(client, access, "update_navigation", {
            "id": menu["id"], "version": updated_menu["version"], "title": "Forbidden menu"})),
              role + " cannot modify navigation")


def walk_layout(blocks):
    for block in blocks:
        yield block
        yield from walk_layout(block.get("children", []))


def layout_editing_tests(client, admin_access, editor_access, content_access, readonly_access, footer_id):
    original = assert_tool(client, admin_access, "get_layout", {"id": footer_id, "type": "template_part"})
    target = next(block for block in walk_layout(original["blocks"])
                  if block["name"] == "core/paragraph" and "Nested footer link area" in block["content"])
    nested_path = target["path"]
    check(len(nested_path) == 3 and target["attributes"] == {},
          "layout inspection exposes nested block paths and block attributes")
    replacement = "<!-- wp:paragraph --><p>Replaced nested footer text</p><!-- /wp:paragraph -->"
    replacement += "<!-- wp:paragraph --><p>Temporary second paragraph</p><!-- /wp:paragraph -->"
    navigation_block = '<!-- wp:navigation {"ref":' + str(FIXTURES["navigation"]) + '} /-->'
    operations = [
        {"action": "replace", "path": nested_path, "content": replacement},
        {"action": "insert_after", "path": nested_path, "content": navigation_block},
        {"action": "remove", "path": nested_path[:-1] + [nested_path[-1] + 2]},
        {"action": "insert_before", "path": nested_path, "content": "<!-- wp:paragraph --><p>Leading nested footer text</p><!-- /wp:paragraph -->"},
    ]
    changed = assert_tool(client, admin_access, "update_layout", {
        "id": footer_id, "type": "template_part", "version": original["version"], "operations": operations})
    check(changed["version"] != original["version"] and "Replaced nested footer text" in changed["content"]
          and "Nested footer link area" not in changed["content"] and "Temporary second paragraph" not in changed["content"]
          and "Leading nested footer text" in changed["content"],
          "sequential nested layout operations replace, insert before/after and remove blocks")
    check('<footer class="wp-block-group fixture-footer">' in changed["content"]
          and '<div class="wp-block-group fixture-nested">' in changed["content"]
          and "Updated footer fixture <strong>bold unchanged</strong>" in changed["content"],
          "nested block surgery preserves parent wrapper HTML and untouched sibling markup")
    check('<!-- wp:pattern {"slug":"mcp-test/preserved-footer"} /-->' in changed["content"]
          and "Resolved footer pattern fixture" not in changed["content"],
          "targeted layout edits preserve untouched theme pattern references")
    inserted_nav = [block for block in walk_layout(changed["blocks"]) if block["name"] == "core/navigation"]
    check(len(inserted_nav) == 1 and inserted_nav[0]["attributes"]["ref"] == FIXTURES["navigation"],
          "layout insertion can attach an existing reusable navigation to the footer")
    current = assert_tool(client, readonly_access, "get_layout", {"id": footer_id, "type": "template_part"})
    check(current["content"] == changed["content"], "read-only appearance scope can inspect the persisted footer block tree")
    paragraph = next(block for block in walk_layout(current["blocks"]) if block["name"] == "core/paragraph")
    bad_operations = [
        {"action": "replace", "path": paragraph["path"], "content": "<!-- wp:paragraph --><p>Partial write must not persist</p><!-- /wp:paragraph -->"},
        {"action": "remove", "path": [999]},
    ]
    check(not tool_ok(tool(client, admin_access, "update_layout", {
        "id": footer_id, "type": "template_part", "version": current["version"], "operations": bad_operations})),
          "invalid later layout operation rejects the complete batch before writing")
    after_invalid = assert_tool(client, admin_access, "get_layout", {"id": footer_id, "type": "template_part"})
    check(after_invalid["version"] == current["version"] and after_invalid["content"] == current["content"],
          "rejected layout operation batch leaves persisted content and version unchanged")
    check(not tool_ok(tool(client, admin_access, "update_layout", {
        "id": footer_id, "type": "template_part", "version": original["version"],
        "operations": [{"action": "remove", "path": paragraph["path"]}]})), "layout update rejects a stale version")
    for invalid, label in (({"action": "remove", "path": paragraph["path"], "content": "unexpected"}, "content on remove"),
                           ({"action": "replace", "path": paragraph["path"], "content": "<?php die(); ?>"}, "PHP fragments"),
                           ({"action": "insert_before", "path": ["0"], "content": "<!-- wp:separator /-->"}, "noninteger paths"),
                           ({"action": "replace", "path": paragraph["path"], "content": "<!-- wp:paragraph --><p>Unclosed</p>"}, "unclosed block fragments"),
                           ({"action": "replace", "path": paragraph["path"], "content": '<!-- wp:paragraph {"align":} --><p>Malformed</p><!-- /wp:paragraph -->'}, "malformed attribute JSON")):
        check(not tool_ok(tool(client, admin_access, "update_layout", {
            "id": footer_id, "type": "template_part", "version": current["version"], "operations": [invalid]})),
              "layout operations reject " + label)
    for access, role in ((editor_access, "editor"), (content_access, "content-only token")):
        check(not tool_ok(tool(client, access, "get_layout", {"id": footer_id, "type": "template_part"})),
              role + " cannot inspect privileged template layouts")
    for access, role in ((editor_access, "editor"), (readonly_access, "read-only appearance token")):
        check(not tool_ok(tool(client, access, "update_layout", {
            "id": footer_id, "type": "template_part", "version": current["version"],
            "operations": [{"action": "remove", "path": paragraph["path"]}]})),
              role + " cannot invoke layout mutation")
    saved = assert_tool(client, admin_access, "get_template", {"id": footer_id, "type": "template_part"})
    storage = fixture_storage(saved["wp_id"])
    check(storage["post_content"] == changed["content"] and storage["footer_file"] == FIXTURES["footer_content"],
          "all layout edits remain database overrides and never touch theme source files")


if __name__ == "__main__":
    main()
