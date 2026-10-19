"""Real WordPress smoke tests against a disposable local installation only.

Requires an installed test site at /tmp/itia-wordpress-test, serving localhost:8765,
with DB_NAME=itia_test. The plugin must be installed and active. Never use a live DB.
"""
import http.cookiejar
import json
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path('/tmp/itia-wordpress-test')
URL = 'http://127.0.0.1:8765'
checks = 0


def wp(*args):
    return subprocess.check_output(['wp', f'--path={ROOT}', *args], text=True).strip()


def php(code):
    return wp('eval', code)


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def request(path='/', headers=None, data=None, opener=None):
    headers = headers or {'User-Agent': 'curl/8.5.0'}
    req = urllib.request.Request(URL + path, headers=headers,
        data=urllib.parse.urlencode(data).encode() if data is not None else None)
    try:
        response = (opener or urllib.request.build_opener()).open(req)
    except urllib.error.HTTPError as error:
        response = error
    return response.status, response.read().decode('utf-8'), response.headers


def totals():
    return json.loads(php('global $wpdb; echo wp_json_encode((new \\ChanceryLane\\AgentFinder\\Repository($wpdb))->totals(7));'))


def count():
    return sum(map(int, totals().values())) if totals() else 0


def login(user='agent_test', password='temporary-local-test-only'):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    request('/wp-login.php', opener=opener)
    request('/wp-login.php', data={'log': user, 'pwd': password, 'wp-submit': 'Log In',
        'redirect_to': URL + '/wp-admin/', 'testcookie': '1'}, opener=opener)
    return opener


def nonce(markup, action):
    for form in re.findall(r'<form\b.*?</form>', markup, re.S):
        if f'value="{action}"' in form:
            return re.search(r'name="_wpnonce" value="([^"]+)"', form)[1]
    raise AssertionError(f'Missing nonce form: {action}')


check(php("echo DB_NAME . '|' . get_option('blogname');") == 'itia_test|Agent Finder Test', 'Refuse any non-test database')
wp('rewrite', 'structure', '/%postname%/')
wp('rewrite', 'flush')
php("global $wpdb; (new \\ChanceryLane\\AgentFinder\\Repository($wpdb))->clear(); update_option('itia_settings', ['enabled'=>false,'retention'=>7]);")
check(request()[0] == 200, 'Fixture home page must serve HTML')
check(count() == 0, 'Activation/paused observation must store nothing')

admin = login()
status, markup, _ = request('/wp-admin/tools.php?page=is-this-an-agent', opener=admin)
check(status == 200 and 'No clues in the notebook yet.' in markup, 'Admin empty state renders')
status, _, _ = request('/wp-admin/admin-post.php', opener=admin,
    data={'action': 'itia_settings', '_wpnonce': 'invalid', 'enabled': '1'})
check(status == 403, 'Settings require a valid nonce')
check(json.loads(wp('option', 'get', 'itia_settings', '--format=json'))['enabled'] is False, 'Rejected mutation leaves settings unchanged')
request('/wp-admin/admin-post.php', opener=admin, data={'action': 'itia_settings',
    '_wpnonce': nonce(markup, 'itia_settings'), 'enabled': '1', 'retention': '7'})
check(json.loads(wp('option', 'get', 'itia_settings', '--format=json'))['enabled'] is True, 'Admin can enable observation')

request(headers={'User-Agent': 'curl/8.5.0', 'X-Forwarded-For': '87.81.230.42'})
check(int(totals().get('tool', 0)) == 1 and not totals().get('possible_muse'), 'HTTP request stored once without trusting a forwarded address')
request(headers={'User-Agent': 'curl/8.5.0', 'X-Agent': 'Muse'})
check(int(totals().get('declared_muse', 0)) == 1, 'X-Agent self-introduction is its own bucket')

before = count()
for headers in [{'User-Agent': 'curl/8.5.0', 'DNT': '1'},
                {'User-Agent': 'curl/8.5.0', 'Sec-GPC': '1'},
                {'User-Agent': 'Mozilla/5.0 Chrome/154.0.0.0', 'Sec-Fetch-Mode': 'navigate', 'Accept-Encoding': 'gzip, br', 'Accept-Language': 'en-GB'}]:
    request(headers=headers)
for path in ['/?private=visitor@example.test', '/?s=private', '/wp-json/', '/feed/', '/does-not-exist/']:
    request(path)
    check(count() == before, f'Excluded route must not be counted: {path}')
request(opener=admin)
request(data={'private': 'do not observe POST'})
check(count() == before, 'Opt-outs, normal browsers, sensitive routes, logged-in visitors and POST are excluded')

for name, password in [('itia-public-fixture', ''), ('itia-protected-fixture', 'test-only')]:
    wp('post', 'create', '--post_type=page', '--post_status=publish',
       f'--post_name={name}', f'--post_title={name}', f'--post_password={password}', '--porcelain')
request('/itia-public-fixture/')
check(count() == before + 1, 'Public singular HTML page is counted')
before = count()
request('/itia-protected-fixture/')
check(count() == before, 'Password-protected page is excluded even though its form is public')

# Simulate an early responder, exactly where the Markdown companion exits.
fixture = ROOT / 'wp-content/mu-plugins/itia-response-fixtures.php'
fixture.parent.mkdir(exist_ok=True)
fixture.write_text('''<?php
add_action('template_redirect', function () {
    if (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === '/markdown-fixture/') {
        header('Content-Type: text/markdown'); echo '# Synthetic Markdown'; exit;
    }
});
add_filter('template_include', function ($template) {
    if (isset($_SERVER['HTTP_X_ITIA_TEST_TYPE'])) {
        if ($_SERVER['HTTP_X_ITIA_TEST_TYPE'] === 'error') { status_header(500); }
        else { header('Content-Type: application/json'); }
    }
    return $template;
}, 1);
''')
try:
    check(request('/markdown-fixture/')[2].get_content_type() == 'text/markdown', 'Early Markdown response fixture is active')
    request(headers={'User-Agent': 'curl/8.5.0', 'X-Itia-Test-Type': 'json'})
    request(headers={'User-Agent': 'curl/8.5.0', 'X-Itia-Test-Type': 'error'})
    check(count() == before, 'Markdown, non-HTML and error responses must not increment counters')
finally:
    # A leftover fixture would silently alter every later run.
    fixture.unlink()

status, markup, _ = request('/wp-admin/tools.php?page=is-this-an-agent', opener=admin)
check(status == 200 and 'User-Agent names an HTTP tool' in markup and 'Sent an X-Agent self-introduction' in markup, 'Stored clues are visible on the dashboard')
check('87.81.230.42' not in markup and 'visitor@example.test' not in markup, 'Dashboard contains no raw request data')
columns = json.loads(php('global $wpdb; echo wp_json_encode($wpdb->get_col("SHOW COLUMNS FROM {$wpdb->prefix}itia_daily"));'))
check(columns == ['observed_day', 'category', 'clues', 'rule_version', 'hits'], 'Actual database schema contains only aggregate fields')

# Seed only synthetic aggregate data to exercise expiry, not raw visitor records.
php('''global $wpdb; $repo = new \\ChanceryLane\\AgentFinder\\Repository($wpdb);
$finding = ['category'=>'tool','clues'=>4,'rule_version'=>\\ChanceryLane\\AgentFinder\\Detector::VERSION];
$repo->record($finding, gmdate('Y-m-d', time()-8*DAY_IN_SECONDS));
$repo->record($finding, gmdate('Y-m-d', time()-DAY_IN_SECONDS));
$repo->prune(7);
echo '';''')
check(int(php('global $wpdb; echo $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}itia_daily WHERE observed_day < CURDATE() - INTERVAL 6 DAY");')) == 0, 'Expired aggregates are deleted from the database')
request('/wp-admin/admin-post.php', opener=admin, data={'action': 'itia_settings',
    '_wpnonce': nonce(markup, 'itia_settings'), 'enabled': '1', 'retention': '1'})
check(int(php('global $wpdb; echo $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}itia_daily WHERE observed_day < CURDATE()");')) == 0, 'Shortening retention prunes immediately')

php("if (!username_exists('itia_subscriber')) { wp_create_user('itia_subscriber', 'temporary-subscriber-only', 'subscriber@example.test'); }")
subscriber = login('itia_subscriber', 'temporary-subscriber-only')
check(request('/wp-admin/tools.php?page=is-this-an-agent', opener=subscriber)[0] == 403, 'Subscribers cannot read dashboard')
check(request('/wp-admin/admin-post.php', opener=subscriber, data={'action':'itia_clear', '_wpnonce':nonce(markup, 'itia_clear')})[0] == 403, 'Subscribers cannot delete counts')

request('/wp-admin/admin-post.php', opener=admin, data={'action':'itia_clear', '_wpnonce':nonce(markup, 'itia_clear')})
check(count() == 0, 'Admin deletion clears the actual table')
request()
check(count() == 1, 'Observation continues after clearing')
wp('plugin', 'deactivate', 'is-this-an-agent')
check(int(php('global $wpdb; echo $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}itia_daily");')) == 0, 'Deactivation clears data')
check(php("echo wp_next_scheduled('itia_cleanup') ? 'scheduled' : 'none';") == 'none', 'Deactivation removes cron job')
wp('plugin', 'activate', 'is-this-an-agent')
check(json.loads(wp('option', 'get', 'itia_settings', '--format=json'))['enabled'] is False, 'Reactivation stays paused')

wp('plugin', 'uninstall', 'is-this-an-agent', '--deactivate', '--skip-delete')
check(php('global $wpdb; echo $wpdb->get_var("SHOW TABLES LIKE \'{$wpdb->prefix}itia_daily\'") ?: "gone";') == 'gone', 'Uninstall removes aggregate table')
check(php("echo get_option('itia_settings', 'gone');") == 'gone', 'Uninstall removes settings')
check(php("echo wp_next_scheduled('itia_cleanup') ? 'scheduled' : 'none';") == 'none', 'Uninstall removes scheduled cleanup')
wp('plugin', 'activate', 'is-this-an-agent')

print(f'Passed {checks} WordPress integration checks.')
