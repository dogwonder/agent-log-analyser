<?php

declare(strict_types=1);

require_once __DIR__ . '/../is-this-an-agent/includes/Detector.php';
require_once __DIR__ . '/../is-this-an-agent/includes/Repository.php';

use ChanceryLane\AgentFinder\Detector;
use ChanceryLane\AgentFinder\Repository;

define('DAY_IN_SECONDS', 86400);
$checks = 0;
function check(bool $pass, string $message): void {
    global $checks;
    ++$checks;
    if (!$pass) {
        throw new RuntimeException($message);
    }
}
$detector = new Detector();
$fingerprint = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36';
$chrome = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36';
$normal = ['HTTP_USER_AGENT' => $chrome, 'HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_SEC_CH_UA' => 'Chromium', 'HTTP_ACCEPT_ENCODING' => 'gzip, deflate, br', 'HTTP_ACCEPT_LANGUAGE' => 'en-GB,en;q=0.9', 'REMOTE_ADDR' => '87.81.230.42'];
$lang = ['HTTP_ACCEPT_LANGUAGE' => 'en-GB'];
$inspect = static fn(array $server, bool $https = true, string $day = '2026-10-19') => $detector->inspect($server, $https, $day);
check($inspect($normal) === null, 'A normal Linux browser inside the pool must not be Muse');
check($inspect(array_replace($normal, ['HTTP_USER_AGENT' => $fingerprint])) === null, 'Exact old Chrome string alone must not identify Muse');
check($inspect([]) === null, 'Empty headers must not be suspicious');
check($inspect(['HTTP_USER_AGENT' => ['invalid']]) === null, 'Malformed header values must not crash');
check($inspect(['HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/144.0']) === null, 'Firefox does not require Chrome hints');
check($inspect(['HTTP_USER_AGENT' => 'Mozilla/5.0 Safari/605.1.15']) === null, 'Safari must not be flagged for missing Chrome headers');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_ACCEPT_ENCODING' => 'br'] + $lang) === null, 'Missing headers alone are not enough');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_SEC_FETCH_MODE' => 'navigate'] + $lang) === null, 'Missing Brotli alone is not enough');
check($inspect(array_diff_key($normal, $lang)) === null, 'Missing Accept-Language alone is not enough');
check($inspect(['HTTP_USER_AGENT' => $chrome], false) === null, 'On HTTP only Accept-Language can be judged, and one habit is not enough');
check(!($inspect(['HTTP_USER_AGENT' => 'Mozilla/5.0 HeadlessChrome/154.0.0.0'], false)['clues'] & Detector::MISSING_HEADERS), 'Chrome never sends Fetch Metadata to HTTP origins, so their absence is not a clue there');
check($inspect(['HTTP_USER_AGENT' => $chrome])['category'] === 'possible_automation', 'Two clues may suggest automation without naming an agent');
check($inspect(['HTTP_USER_AGENT' => $fingerprint])['category'] === 'possible_automation', 'Research browser string without the network remains unattributed');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_ACCEPT_ENCODING' => 'gzip, BR;q=1'] + $lang) === null, 'Brotli token matching is case insensitive');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_ACCEPT_ENCODING' => 'gzip, br'])['clues'] === (Detector::MISSING_HEADERS | Detector::NO_LANGUAGE), 'Missing headers and Accept-Language are two habits');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_SEC_CH_UA' => 'Chromium', 'HTTP_ACCEPT_ENCODING' => 'gzip'])['clues'] === (Detector::NO_BROTLI | Detector::NO_LANGUAGE), 'No Brotli and no Accept-Language are two habits');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_ACCEPT_ENCODING' => 'zebra'] + $lang)['category'] === 'possible_automation', 'Substring br is not a Brotli token');

$curl = ['HTTP_USER_AGENT' => 'curl/8.5.0', 'REMOTE_ADDR' => '87.81.224.0'];
foreach (['87.81.224.0', '87.81.230.42', '87.81.255.255', '::ffff:87.81.230.42'] as $ip) {
    $finding = $inspect(array_replace($curl, ['REMOTE_ADDR' => $ip]));
    check($finding['category'] === 'possible_muse', 'Exact tool and pool should be a possible Muse sighting');
    check((bool) ($finding['clues'] & Detector::RESEARCH_NETWORK), 'Named attribution must explain its network clue');
}
foreach (['87.81.223.255', '87.82.224.1', '104.28.1.1', '2001:db8::1', 'garbage', '87.81.230.42, 1.2.3.4', ''] as $ip) {
    check($inspect(array_replace($curl, ['REMOTE_ADDR' => $ip]))['category'] === 'tool', 'Other or invalid network is just a tool');
}
check($inspect(array_replace($curl, ['HTTP_USER_AGENT' => 'curl/8.6.0']))['category'] === 'tool', 'Different curl release must not inherit the specific research attribution');
check($inspect($curl, true, Detector::MUSE_RULE_EXPIRES)['category'] === 'tool', 'Attribution expires at its review deadline');
check($inspect($curl, true, '2026-10-08')['category'] === 'tool', 'Rule cannot predate its evidence');
check($inspect(['HTTP_USER_AGENT' => 'curl/8.5.0', 'HTTP_X_FORWARDED_FOR' => '87.81.230.42', 'HTTP_CF_CONNECTING_IP' => '87.81.230.42'])['category'] === 'tool', 'Spoofed proxy headers must never supply attribution');
check($inspect(['HTTP_USER_AGENT' => $fingerprint, 'REMOTE_ADDR' => '87.81.230.42'])['category'] === 'possible_muse', 'Exact fetcher fingerprint plus independent clues may match');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'REMOTE_ADDR' => '87.81.230.42'])['category'] === 'possible_automation', 'Generic modern Chrome in the pool must not be named Muse');
check($inspect(['HTTP_USER_AGENT' => 'Mozilla/5.0 HeadlessChrome/154.0.0.0'])['category'] === 'tool', 'Headless is automation, not an agent identity');
foreach (['axios/1.7.2', 'node-fetch/1.0 (+https://github.com/bitinn/node-fetch)', 'okhttp/4.12.0', 'Python/3.12 aiohttp/3.9.5', 'Scrapy/2.11.2 (+https://scrapy.org)', 'Java/17.0.2', 'Java-http-client/21.0.1', 'Apache-HttpClient/4.5.14 (Java/17.0.2)'] as $ua) {
    check($inspect(['HTTP_USER_AGENT' => $ua])['category'] === 'tool', "Default library User-Agent is a tool: $ua");
}
foreach (['Javascript-Client/1.0', 'axiosity/1.0', 'Mozilla/5.0 (compatible; axios/1.7.2)'] as $ua) {
    check($inspect(['HTTP_USER_AGENT' => $ua]) === null, "Tool names only match as the leading product: $ua");
}

foreach (['Muse' => 'muse', 'Instinct' => 'instinct', 'openclaw' => 'openclaw', 'OpenClaw/0.9' => 'openclaw', 'Dot' => 'dot', 'Dots/1.0' => 'dot', 'Grok' => 'grok', 'GrokBot/1.0' => 'grok', 'Navigator' => 'other'] as $name => $category) {
    check($inspect(['HTTP_X_AGENT' => $name])['category'] === 'declared_' . $category, 'An introduction must remain a claim');
}
foreach (['Muse/1.0' => 'muse', 'Instinct/1.0' => 'instinct', 'Mozilla/5.0 (compatible; GrokBot/1.0)' => 'grok', 'Dots/1.0' => 'dot'] as $ua => $category) {
    check($inspect(['HTTP_USER_AGENT' => $ua])['category'] === 'declared_' . $category, 'Only bounded product names should match');
}
// Self-declared bots are covered by the Markdown companion and the logs, even when they also claim Chrome.
foreach ([
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot) Chrome/119.0.6045.214 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)',
    'meta-externalfetcher/1.1',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Google-Agent',
] as $ua) {
    check($inspect(['HTTP_USER_AGENT' => $ua, 'REMOTE_ADDR' => '87.81.230.42']) === null, "Self-declared bot is out of scope: $ua");
}
check($inspect(['HTTP_X_AGENT' => 'ClaudeBot'])['category'] === 'declared_other', 'X-Agent introductions are still counted');

// Web Bot Auth: signed requests with an ordinary browser User-Agent.
$signed = $normal + ['HTTP_SIGNATURE' => 'sig1=:YWJj:', 'HTTP_SIGNATURE_INPUT' => 'sig1=("@authority" "signature-agent");tag="web-bot-auth"'];
$finding = $inspect($signed + ['HTTP_SIGNATURE_AGENT' => '"https://chatgpt.com"']);
check($finding['category'] === 'signed_chatgpt' && $finding['clues'] === Detector::SIGNED, 'A known signer is named');
check($inspect($signed + ['HTTP_SIGNATURE_AGENT' => 'sig1="https://ChatGPT.com"'])['category'] === 'signed_chatgpt', 'Signer matching ignores case and dictionary form');
foreach (['"https://chatgpt.com.evil.test"', '"https://agent.example.test"', '', 'garbage'] as $agent) {
    $finding = $inspect($signed + ['HTTP_SIGNATURE_AGENT' => $agent]);
    check($finding['category'] === 'signed_other', "Unknown or missing signer is not named: $agent");
    check(!str_contains(json_encode($finding), 'example') && !str_contains(json_encode($finding), 'evil'), 'Signer text is never stored');
}
check($inspect($normal + ['HTTP_SIGNATURE_AGENT' => '"https://chatgpt.com"']) === null, 'Signature-Agent without signature headers is not a signed request');
check($inspect(array_replace($signed, ['HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; ClaudeBot/1.0)'])) === null, 'Signed self-declared bots are still out of scope');
check(count(Detector::clues(Detector::ALL_CLUES)) === 10 && (Detector::SIGNED | Detector::NO_LANGUAGE) <= Detector::ALL_CLUES, 'Every clue fits the storage bound');
foreach (Detector::categories() as $category => $_) {
    check(strlen($category) <= 32, "Category fits the table: $category");
}
foreach (['DotBot/1.0', 'Museum/1.0', 'Instinctive/1.0', 'NotGrok/1.0', 'Mozilla/5.0 (https://example.test/Muse)'] as $ua) {
    check($inspect(['HTTP_USER_AGENT' => $ua]) === null, 'Similar words and URLs are not product introductions');
}
$secret = '<script>alert("visitor@example.test")</script>';
$finding = $inspect(['HTTP_X_AGENT' => $secret, 'REMOTE_ADDR' => '198.51.100.42', 'REQUEST_URI' => '/private?email=visitor@example.test', 'HTTP_COOKIE' => 'session=secret']);
check(array_keys($finding) === ['category', 'clues', 'rule_version'], 'Only bounded data crosses the storage boundary');
check(!str_contains(json_encode($finding), 'visitor') && !str_contains(json_encode($finding), '198.51'), 'Raw request details must not survive classification');
check($finding['category'] === 'declared_other', 'Unknown introductions must use a fixed bucket');
check(count(Detector::clues(Detector::TOOL | Detector::RESEARCH_NETWORK)) === 2, 'Show each supporting clue');
$now = strtotime('2026-10-19 12:00:00 UTC');
check(Repository::cutoff(7, $now) === '2026-10-13', 'Seven UTC dates include today');
check(Repository::cutoff(1, $now) === '2026-10-19', 'One day keeps today only');
check(Repository::cutoff(999, $now) === '2026-09-20', 'Retention cannot exceed thirty calendar dates');
echo "Passed $checks detector and privacy checks.\n";
