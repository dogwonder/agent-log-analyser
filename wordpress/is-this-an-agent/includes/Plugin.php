<?php

declare(strict_types=1);

namespace ChanceryLane\AgentFinder;

final class Plugin
{
    private Repository $repository;
    private ?array $pending = null;
    private string $day = '';

    public function __construct(private readonly string $file)
    {
        global $wpdb;
        $this->repository = new Repository($wpdb);
    }

    public function boot(): void
    {
        add_action('init', [$this, 'maintain']);
        // The Markdown companion exits at template_redirect:1. Only requests
        // that reach HTML template selection are considered here.
        add_filter('template_include', [$this, 'observe'], PHP_INT_MAX);
        add_action('shutdown', [$this, 'finish']);
        add_action('itia_cleanup', [$this, 'cleanup']);
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_post_itia_settings', [$this, 'save']);
        add_action('admin_post_itia_clear', [$this, 'clear']);
        add_action('admin_init', [$this, 'privacy']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
    }

    public static function activate(bool $networkWide = false): void
    {
        if ($networkWide) {
            wp_die('Please activate Is this an agent? separately on each site. Network activation is not supported.');
        }
        global $wpdb;
        (new Repository($wpdb))->install();
        add_option('itia_settings', ['enabled' => false, 'retention' => 7], '', false);
        update_option('itia_schema', 1, false);
        if (!wp_next_scheduled('itia_cleanup')) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'itia_cleanup');
        }
    }

    public static function deactivate(): void
    {
        wp_clear_scheduled_hook('itia_cleanup');
        global $wpdb;
        // No abandoned visitor statistics with a disabled retention job.
        (new Repository($wpdb))->clear();
        delete_option('itia_last_cleanup');
        $settings = self::settings();
        $settings['enabled'] = false;
        update_option('itia_settings', $settings, false);
    }

    public static function settings(): array
    {
        $settings = get_option('itia_settings', []);
        $settings = is_array($settings) ? $settings : [];
        $days = (int) ($settings['retention'] ?? 7);
        return ['enabled' => !empty($settings['enabled']), 'retention' => in_array($days, [1, 7, 14, 30], true) ? $days : 7];
    }

    public function maintain(): void
    {
        if ((int) get_option('itia_schema', 0) !== 1) {
            $this->repository->install();
            update_option('itia_schema', 1, false);
        }
        if (!wp_next_scheduled('itia_cleanup')) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'itia_cleanup');
        }
        // WP-Cron can be late. Also prune on the first WordPress request each UTC day.
        if (get_option('itia_last_cleanup') !== gmdate('Y-m-d')) {
            $this->cleanup();
        }
    }

    public function cleanup(): void
    {
        $this->repository->prune(self::settings()['retention']);
        update_option('itia_last_cleanup', gmdate('Y-m-d'), false);
    }

    public function observe(string $template): string
    {
        $this->pending = null;
        if (!self::settings()['enabled'] || is_admin() || is_user_logged_in()
            || wp_doing_ajax() || wp_doing_cron() || (defined('REST_REQUEST') && REST_REQUEST)
            || (defined('WP_CLI') && WP_CLI)
            || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
            || ($_SERVER['HTTP_DNT'] ?? '') === '1' || ($_SERVER['HTTP_SEC_GPC'] ?? '') === '1'
            || is_search() || is_preview() || is_404() || is_feed() || is_embed() || is_trackback()) {
            return $template;
        }
        // Start with a narrow public surface. Never inspect private, passworded,
        // search or account routes, including routes with application query data.
        if (is_singular()) {
            $post = get_queried_object();
            if (!$post instanceof \WP_Post || !is_post_publicly_viewable($post) || $post->post_password !== '') {
                return $template;
            }
        } elseif (!is_home() && !is_front_page()) {
            return $template;
        }
        if (!empty($_GET) || !apply_filters('itia_observe_request', true)) {
            return $template;
        }
        $this->day = gmdate('Y-m-d');
        $this->pending = (new Detector())->inspect($_SERVER, is_ssl(), $this->day);
        return $template;
    }

    public function finish(): void
    {
        if ($this->pending === null) {
            return;
        }
        $finding = $this->pending;
        $this->pending = null; // At most once, even if shutdown is invoked twice.
        $status = http_response_code();
        if ($status !== 200) {
            return;
        }
        $error = error_get_last();
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
            return;
        }
        $html = false;
        foreach (headers_list() as $header) {
            if (stripos($header, 'Content-Type:') === 0) {
                $html = (bool) preg_match('~^Content-Type:\s*text/html(?:\s*;|\s*$)~i', $header);
            }
        }
        if ($html) {
            $this->repository->record($finding, $this->day);
        }
    }

    public function menu(): void
    {
        add_management_page('Is this an agent?', 'Is this an agent?', 'manage_options', 'is-this-an-agent', [$this, 'render']);
    }

    public function assets(string $hook): void
    {
        if ($hook === 'tools_page_is-this-an-agent') {
            wp_enqueue_style('itia-admin', plugins_url('assets/admin.css', $this->file), [], '0.1.1');
        }
    }

    public function save(): void
    {
        $this->authorise('itia_settings');
        $days = isset($_POST['retention']) && is_scalar($_POST['retention']) ? (int) $_POST['retention'] : 7;
        update_option('itia_settings', [
            'enabled' => isset($_POST['enabled']) && $_POST['enabled'] === '1',
            'retention' => in_array($days, [1, 7, 14, 30], true) ? $days : 7,
        ], false);
        $this->cleanup();
        $this->redirect();
    }

    public function clear(): void
    {
        $this->authorise('itia_clear');
        $this->repository->clear();
        $this->redirect();
    }

    private function authorise(string $action): void
    {
        if (!current_user_can('manage_options') || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            wp_die('You cannot change these settings.', '', ['response' => 403]);
        }
        check_admin_referer($action);
    }

    private function redirect(): void
    {
        wp_safe_redirect(admin_url('tools.php?page=is-this-an-agent&updated=1'));
        exit;
    }

    public function privacy(): void
    {
        wp_add_privacy_policy_content('Is this an agent?',
            '<p class="privacy-policy-tutorial">Review this wording and document your lawful basis before enabling observation. Partial IP masking or aggregate storage alone does not establish GDPR compliance. Adapt the retention period to your setting. Your host and other plugins may keep separate logs.</p>' .
            '<p>We use Is this an agent? to count requests that may come from automated assistants. For eligible public HTML requests, it checks request headers and the connection IP address in memory. It stores only site-wide daily totals by a fixed classification and clue set, plus a rule version. It does not store IP addresses, IP hashes, raw headers, page addresses or visitor identifiers, set cookies, run browser fingerprinting scripts or send data to an external service. Classifications are uncertain and are not used to restrict access. Logged-in requests and requests sending Do Not Track or Global Privacy Control are excluded.</p>' .
            '<p>Daily totals are retained for ' . (int) self::settings()['retention'] . ' UTC calendar days including today. Expired totals are deleted when the scheduled cleanup or next WordPress request runs. Site administrators can delete all totals at any time. Backups may retain earlier copies under our separate backup policy.</p>'
        );
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die('You cannot view this page.', '', ['response' => 403]);
        }
        $settings = self::settings();
        $this->cleanup();
        $totals = $this->repository->totals($settings['retention']);
        $rows = $this->repository->rows($settings['retention']);
        $categories = Detector::categories();
        $awaitingStart = !$settings['enabled'] && !$totals;
        $range = gmdate('j M Y', strtotime(Repository::cutoff($settings['retention']) . ' UTC')) . ' – ' . gmdate('j M Y');
        ?>
        <div class="wrap itia">
            <h1>Is this an agent?</h1>
            <p class="description itia-intro">Muse? Dot? Grok? Or just somebody with an unusual browser? We collect clues. The question mark stays.</p>
            <?php if (isset($_GET['updated'])) : ?>
                <div class="notice notice-success inline"><p>Done. Your field notes are up to date.</p></div>
            <?php endif; ?>
            <?php if (!$settings['enabled']) : ?>
                <section class="postbox itia-observation itia-observation-off" aria-labelledby="itia-observation-title">
                    <div class="inside">
                        <h2 id="itia-observation-title">Observation is off — turn it on to collect results</h2>
                        <p>The plugin is installed, but it is not collecting new sightings. Enable observation to start counting eligible public HTML requests from now on. Earlier visits cannot be recovered.</p>
                        <?php if ($totals) : ?><p>Any totals below are retained from earlier observation. They will continue to expire under your retention setting.</p><?php endif; ?>
                        <p class="description">Only daily counts and fixed clues are saved. No IP addresses or visitor histories are stored. Review the suggested wording in <a href="<?php echo esc_url(admin_url('options-privacy.php')); ?>">Settings → Privacy</a> before starting.</p>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <input type="hidden" name="action" value="itia_settings">
                            <input type="hidden" name="enabled" value="1">
                            <input type="hidden" name="retention" value="<?php echo (int) $settings['retention']; ?>">
                            <?php wp_nonce_field('itia_settings'); ?>
                            <?php submit_button('Enable observation and collect results', 'primary', 'submit', false); ?>
                            <span class="itia-action-note">Keeps your current <?php echo (int) $settings['retention']; ?>-day retention setting.</span>
                        </form>
                    </div>
                </section>
            <?php else : ?>
                <div class="notice notice-info inline itia-observation-on"><p><strong>Observation is on.</strong> Eligible public HTML requests are being checked for clues. Matching requests appear below. <a href="#itia-settings">Manage observation settings</a>.</p></div>
            <?php endif; ?>
            <h2 class="itia-section-title">Summary · <?php echo esc_html($range); ?></h2>
            <p class="description">Counts are matching HTML requests recorded by WordPress, not people, unique agents or verified identities. Pages answered by a CDN or static cache are not counted. Dates are UTC.</p>
            <h3 class="itia-group-title">The ones that caught our eye</h3>
            <div class="itia-cards">
                <?php foreach (['possible_muse', 'possible_automation', 'tool'] as $key) : ?>
                    <section class="postbox itia-card itia-card-<?php echo esc_attr($key); ?>"><div class="inside">
                        <h4 class="itia-label"><?php echo esc_html($categories[$key][0]); ?></h4>
                        <p class="itia-count"><?php echo $awaitingStart ? '<span aria-label="Observation has not started">—</span>' : esc_html(number_format_i18n((int) ($totals[$key] ?? 0))); ?></p>
                        <span class="itia-tag"><?php echo $awaitingStart ? 'Enable observation to collect results' : 'Unconfirmed · matching requests'; ?></span>
                        <p><?php echo esc_html($categories[$key][1]); ?></p>
                    </div></section>
                <?php endforeach; ?>
            </div>
            <section>
                <h3 class="itia-group-title">The ones who introduced themselves</h3>
                <p class="description">A name badge is useful. It is also easy to make your own. These claims are unverified.</p>
                <div class="itia-introductions">
                    <?php foreach (['declared_muse', 'declared_dot', 'declared_grok', 'declared_other'] as $key) : ?>
                        <div class="postbox itia-card itia-card-declared"><div class="inside"><h4 class="itia-label"><?php echo esc_html($categories[$key][0]); ?></h4>
                            <p class="itia-count"><?php echo $awaitingStart ? '<span aria-label="Observation has not started">—</span>' : esc_html(number_format_i18n((int) ($totals[$key] ?? 0))); ?></p>
                            <span class="itia-tag"><?php echo $awaitingStart ? 'Enable observation to collect results' : 'Self-declared · matching requests'; ?></span>
                            <p><?php echo esc_html($categories[$key][1]); ?></p></div></div>
                    <?php endforeach; ?>
                </div>
            </section>
            <h2 class="itia-section-title">The field notes</h2>
            <p class="description">Daily groups with the same clues. No individual visitor trails. Showing up to 200 groups; the totals above include all retained groups.</p>
            <?php if (!$rows) : ?>
                <div class="postbox itia-panel"><div class="inside"><h3>No clues in the notebook yet.</h3><p><?php echo $settings['enabled'] ? 'Observation is running. No matching requests have reached these public HTML templates yet. Zero sightings does not mean zero agents.' : 'Observation is off. Use “Enable observation and collect results” above to start filling the notebook. Installing the plugin alone does not collect results.'; ?></p></div></div>
            <?php else : ?>
                <div class="itia-table"><table class="widefat striped">
                    <caption class="screen-reader-text">Unverified request classifications and their supporting clues</caption>
                    <thead><tr><th scope="col">Day (UTC)</th><th scope="col">Our guess / their claim</th><th scope="col">Requests</th><th scope="col">Why it caught our eye</th></tr></thead>
                    <tbody><?php foreach ($rows as $row) : ?>
                        <tr><td><?php echo esc_html($row['observed_day']); ?></td>
                            <td><?php echo esc_html($categories[$row['category']][0] ?? 'Unknown rule'); ?><br><small>Rule <?php echo (int) $row['rule_version']; ?></small></td>
                            <td><?php echo esc_html(number_format_i18n((int) $row['hits'])); ?></td>
                            <td><ul><?php foreach (Detector::clues((int) $row['clues']) as $clue) : ?><li><?php echo esc_html($clue); ?></li><?php endforeach; ?></ul></td></tr>
                    <?php endforeach; ?></tbody>
                </table></div>
            <?php endif; ?>
            <section class="postbox itia-panel">
                <div class="postbox-header"><h2>How much should we believe this?</h2></div>
                <div class="inside">
                <p>Enough to be curious. Not enough to identify a person, verify an agent, or block a visitor. There are no calibrated probability scores here. A normal-looking browser may still be an assistant.</p>
                <p><strong>Muse:</strong> an experimental rule combines the network observed in <a href="<?php echo esc_url(Detector::SOURCE); ?>">Tom Loosemore’s October 2026 research</a> with a specific curl or browser pattern and automation clues. The pool is not verified as exclusive to Muse. This rule stops assigning new Muse guesses on <?php echo esc_html(Detector::MUSE_RULE_EXPIRES); ?> unless a future plugin release reviews it. Historical guesses remain guesses.</p>
                <p><strong>Dot / Dots and Grok:</strong> self-introductions only. We do not have a supported browser fingerprint for either. A shared Cloudflare address or a Linux browser is never enough to name an agent.</p>
                <p><strong>Blind spots:</strong> only successful public HTML pages, posts and the home page that reach WordPress are eligible. Cache hits, Markdown responses, API calls, archives, searches, query-string URLs, logged-in visitors and privacy opt-outs are excluded. A proxy can hide the network clue or strip headers. These are a partial view, not your total agent traffic.</p>
                <p>Works alongside Markdown for Agents and Statistics. Its Markdown counts and these HTML clues answer different questions; adding them does not produce a count of unique agents.</p>
                </div>
            </section>
            <section class="postbox itia-panel" id="itia-settings">
                <div class="postbox-header"><h2>Observation settings</h2></div>
                <div class="inside">
                <p>No saved IPs, IP hashes, raw headers, URLs, cookies or visitor IDs. No browser tracking script or external lookups. Only fixed daily counters. Review the suggested privacy notice in <a href="<?php echo esc_url(admin_url('options-privacy.php')); ?>">Settings → Privacy</a> and your lawful basis before enabling.</p>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="itia_settings">
                    <?php wp_nonce_field('itia_settings'); ?>
                    <p><label><input type="checkbox" name="enabled" value="1" aria-describedby="itia-enabled-help" <?php checked($settings['enabled']); ?>> <strong>Enable observation to collect results</strong></label></p>
                    <p class="description" id="itia-enabled-help">This must be switched on for new sightings to appear. Check the box and save to observe eligible public HTML requests. Uncheck and save to pause collection; existing counts remain until they expire.</p>
                    <p><label for="itia-retention">Keep daily totals for </label><select id="itia-retention" name="retention">
                        <?php foreach ([1, 7, 14, 30] as $days) : ?><option value="<?php echo $days; ?>" <?php selected($settings['retention'], $days); ?>><?php echo $days; ?> <?php echo $days === 1 ? 'day' : 'days'; ?></option><?php endforeach; ?>
                    </select></p>
                    <p>Shortening retention removes older totals immediately. Pausing keeps existing totals until they expire. Cleanup runs via WP-Cron and on the first WordPress request each UTC day; a site with no traffic needs a system cron for timely deletion.</p>
                    <?php submit_button('Save observation settings', 'primary', 'submit', false); ?>
                </form>
                <hr>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="itia_clear">
                    <?php wp_nonce_field('itia_clear'); ?>
                    <p>Delete the current notebook permanently. Observation continues if enabled. Deactivating the plugin also deletes its totals and pauses observation.</p>
                    <?php submit_button('Delete all field notes', 'secondary', 'submit', false); ?>
                </form>
                </div>
            </section>
        </div>
        <?php
    }
}
