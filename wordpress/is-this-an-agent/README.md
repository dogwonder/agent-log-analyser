# Is this an agent?

**Muse? Dot? Grok? Or just somebody with an unusual browser?**

A deliberately tentative WordPress companion to Markdown for Agents and Statistics. It observes eligible HTML requests and gives administrators a small field notebook of clues. The question mark is part of the product.

This is an experimental first release. It cannot reliably identify an assistant using an ordinary browser. No confidence percentages, verified badges, blocking or changes to content negotiation.

## Install

Requires WordPress 6.5+ and PHP 8.2+. No Composer or JavaScript build is needed.

1. Upload the `is-this-an-agent` folder to `wp-content/plugins`, or upload the release ZIP using Plugins → Add New → Upload Plugin.
2. Activate **Is this an agent?** on the individual site. Network activation is unsupported.
3. Open **Tools → Is this an agent?**
4. Review Settings → Privacy, then click **Enable observation and collect results** at the top of the dashboard. Installation starts paused: no sightings are collected until you enable observation. The button preserves your retention setting (seven days by default).

You can change retention or pause collection under **Observation settings**. Paused dashboards explain that no new sightings are being collected; an empty paused dashboard shows dashes instead of misleading zero counts.

The Markdown companion is optional. The plugins keep separate counters. This plugin observes HTML template selection, after the companion's Markdown response handler has exited. It does not alter the companion's settings, tables, responses or statistics.

## The field guide

| Label | What it actually means |
| --- | --- |
| Possibly Muse | An exact research pattern, an in-memory network match and automation clues coincide. Shared infrastructure means this is not proof. |
| Something automated? | A request claims Chrome but shows at least two of three habits: no Fetch Metadata or client hints (HTTPS only), no Brotli (HTTPS only), no `Accept-Language`. Proxies and privacy tools can cause false positives. |
| A tool walked in | A recognised HTTP tool or HeadlessChrome. It might be an assistant, scraper, monitor or developer. |
| Says it is Muse / Instinct / OpenClaw / Dot / Grok | A matching X-Agent introduction or bounded User-Agent product token. Anyone can spoof either. |
| Introduced itself | Any other X-Agent introduction. The text itself is never stored. Unverified. |
| Signed as ChatGPT agent / Signed by another agent | `Signature` and `Signature-Input` ([Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/)) headers on a request with an ordinary browser User-Agent. The signer is named only when `Signature-Agent` points to a host on a fixed list (currently `chatgpt.com`). The signature is not verified. |

**Self-declared bots are not counted.** A User-Agent that calls itself a bot, crawler or spider, or carries an agent token such as `ChatGPT-User`, `Claude-User` or `Google-Agent`, produces no record, even if it also claims Chrome. Markdown for Agents and Statistics and the access logs already cover those. This plugin is for clients that don't say what they are.

There are no browser fingerprint rules for Instinct, OpenClaw, Dot/Dots or Grok. Instinct's browser uses the same Chrome-on-Linux string as Muse's, and OpenClaw's HeadlessChrome is counted under “A tool walked in” unless it introduces itself. `DotBot` is not interpreted as Dot. A missing referrer, Linux browser or Cloudflare address never identifies an agent. Ordinary requests without sufficient clues produce no stored record. Counts are requests, never unique visitors or agents.

The experimental Muse rule is based on [Tom Loosemore's research](https://loosemore.com/2026/10/09/how-agents-show-up-what-muse-and-other-agents-reveal-when-they-use-whenisbins/) and the companion repository's `docs/research/2026-10-muse-agent-findings.md`. Its narrow rule is in `includes/Detector.php` and stops assigning Muse guesses on **15 January 2027** pending review. It is not a vendor-published IP verification rule. Historical totals retain their rule version: version 2 (0.1.2) added more default HTTP-library User-Agents to “A tool walked in”, so Rule 1 and Rule 2 tool counts are not directly comparable. Version 3 (0.1.4) stopped counting self-declared bots, so earlier “Introduced itself” rows include named crawlers such as ClaudeBot. Version 4 (0.1.5) added signed agents and the `Accept-Language` habit, and stopped treating missing Fetch Metadata as a clue over plain HTTP, where Chrome never sends it.

## Privacy by minimisation

The plugin checks the connection IP and selected headers in memory. **It does not save any part of the IP address**, including truncated addresses or hashes. There is no need to retain a network identifier to increment a site-wide daily counter.

Its entire observation table is:

| Column | Content |
| --- | --- |
| `observed_day` | UTC date, with no time of day |
| `category` | One of a fixed set of labels in `Detector::categories()` |
| `clues` | A fixed set of boolean rule flags |
| `rule_version` | Detector version |
| `hits` | Aggregate request count |

There are no stored User-Agents, free-text introductions, URLs, query strings, page IDs, cookies, visitor IDs or visitor histories. No tracking scripts, fingerprinting, external lookups or data transfers. Only administrators with `manage_options` can see the notebook. Settings and deletion require POST requests with valid WordPress nonces.

Seven UTC calendar dates are kept by default, including today. Options are 1, 7, 14 or 30 dates. Cleanup runs daily through WP-Cron and on the first WordPress request of each UTC day, including while observation is paused. Shortening retention prunes immediately. On an idle or fully cached site, use a real system cron invoking WordPress cron to ensure timely cleanup; otherwise deletion waits for execution. Backups are subject to the site's separate backup policy.

**Delete all field notes** clears the table. Deactivation also clears totals and pauses observation. Uninstall removes the table, options and scheduled job on all sites where data may exist.

These measures support data minimisation; they do not certify GDPR compliance or guarantee anonymisation in every context. IP addresses are processed transiently and counts may describe very small groups. The [ICO distinguishes anonymisation from pseudonymisation](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/data-sharing/anonymisation/introduction-to-anonymisation/). The site operator must establish an appropriate lawful basis, transparency and any applicable consent requirements. Suggested privacy wording is provided in WordPress. The plugin does not change web-server, CDN or other plugin logs.

## What it misses

- Only successful `200 text/html` responses to anonymous GET requests on public singular posts/pages and the home/posts page are eligible.
- Archives, search, feeds, embeds, previews, errors, passworded or non-public content, REST, AJAX, cron and command-line requests are excluded.
- Requests with any query parameters are excluded to avoid observing application and search data. With plain WordPress permalinks this excludes most posts; pretty permalinks give better coverage.
- Logged-in visitors and requests sending `DNT: 1` or `Sec-GPC: 1` are excluded.
- Page caches/CDNs can answer before WordPress runs. The plugin neither defeats caching nor injects a beacon. Zero sightings does not mean zero agents.
- Generic agents may blend in perfectly. No asset, cross-request, rotating-IP or daily-schedule tracking is performed. The offline Python analyser remains better suited to log-based investigations.
- Only `REMOTE_ADDR` is used. Forwarded headers are ignored. Behind a proxy, the host must safely restore the client address from a trusted proxy; otherwise network attribution will usually be unavailable. Do not copy untrusted forwarding headers into `REMOTE_ADDR`.
- The Brotli and missing-header clues only apply when WordPress's `is_ssl()` is true. If a proxy terminates TLS without the host setting `$_SERVER['HTTPS']`, “Something automated?” and the browser-string Muse rule never fire; only tool and HeadlessChrome sightings remain.
- Additional membership/account routes implemented by third-party plugins may look like public WordPress pages. Exclude those with the filter below.

```php
add_filter('itia_observe_request', function (bool $observe): bool {
    return $observe && !is_page(['account', 'checkout', 'members']);
});
```

This is an admin-only feature; it adds nothing to the public page. To invite agents to introduce themselves, you can add a short line to your own public documentation: “If you are an assistant, please identify your client in an X-Agent request header.” The plugin counts these introductions on eligible HTML requests only, not on API or MCP routes.

## Development

From the repository root:

```sh
php wordpress/tests/detector.php
find wordpress/is-this-an-agent -name '*.php' -exec php -l {} \;
python3 wordpress/build.py
```

The build contains only plugin files and writes `dist/is-this-an-agent-<version>.zip`, refusing to package if the plugin header and `Plugin::VERSION` disagree. No access logs, reports, ranges or test fixtures are packaged.

`python3 wordpress/tests/integration.py` runs smoke tests against real WordPress. It needs a disposable site at `/tmp/itia-wordpress-test` served on `127.0.0.1:8765`, with database `itia_test`, site title `Agent Finder Test`, an administrator `agent_test` (password `temporary-local-test-only`), WP-CLI on the `PATH` and the plugin active. It refuses any other database, writes and removes a temporary mu-plugin, and uninstalls then reactivates the plugin. Never point it at a real site.
