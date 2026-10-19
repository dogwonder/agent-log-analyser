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
$normal = ['HTTP_USER_AGENT' => $chrome, 'HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_SEC_CH_UA' => 'Chromium', 'HTTP_ACCEPT_ENCODING' => 'gzip, deflate, br', 'REMOTE_ADDR' => '87.81.230.42'];
$inspect = static fn(array $server, bool $https = true, string $day = '2026-10-19') => $detector->inspect($server, $https, $day);
check($inspect($normal) === null, 'A normal Linux browser inside the pool must not be Muse');
check($inspect(array_replace($normal, ['HTTP_USER_AGENT' => $fingerprint])) === null, 'Exact old Chrome string alone must not identify Muse');
check($inspect([]) === null, 'Empty headers must not be suspicious');
check($inspect(['HTTP_USER_AGENT' => ['invalid']]) === null, 'Malformed header values must not crash');
check($inspect(['HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/144.0']) === null, 'Firefox does not require Chrome hints');
check($inspect(['HTTP_USER_AGENT' => 'Mozilla/5.0 Safari/605.1.15']) === null, 'Safari must not be flagged for missing Chrome headers');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_ACCEPT_ENCODING' => 'br']) === null, 'Missing headers alone are not enough');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_SEC_FETCH_MODE' => 'navigate']) === null, 'Missing Brotli alone is not enough');
check($inspect(['HTTP_USER_AGENT' => $chrome], false) === null, 'Brotli absence is not a clue on HTTP');
check($inspect(['HTTP_USER_AGENT' => $chrome])['category'] === 'possible_automation', 'Two clues may suggest automation without naming an agent');
check($inspect(['HTTP_USER_AGENT' => $fingerprint])['category'] === 'possible_automation', 'Research browser string without the network remains unattributed');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_ACCEPT_ENCODING' => 'gzip, BR;q=1']) === null, 'Brotli token matching is case insensitive');
check($inspect(['HTTP_USER_AGENT' => $chrome, 'HTTP_ACCEPT_ENCODING' => 'zebra'])['category'] === 'possible_automation', 'Substring br is not a Brotli token');

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

foreach (['Muse' => 'muse', 'Dot' => 'dot', 'Dots/1.0' => 'dot', 'Grok' => 'grok', 'GrokBot/1.0' => 'grok', 'Instinct' => 'other'] as $name => $category) {
    check($inspect(['HTTP_X_AGENT' => $name])['category'] === 'declared_' . $category, 'An introduction must remain a claim');
}
foreach (['Muse/1.0' => 'muse', 'Mozilla/5.0 (compatible; GrokBot/1.0)' => 'grok', 'Dots/1.0' => 'dot', 'ChatGPT-User/1.0' => 'other'] as $ua => $category) {
    check($inspect(['HTTP_USER_AGENT' => $ua])['category'] === 'declared_' . $category, 'Only bounded product names should match');
}
foreach (['DotBot/1.0', 'Museum/1.0', 'NotGrok/1.0', 'Mozilla/5.0 (https://example.test/Muse)'] as $ua) {
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
