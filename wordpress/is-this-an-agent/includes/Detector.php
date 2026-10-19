<?php

declare(strict_types=1);

namespace ChanceryLane\AgentFinder;

/** Pure, bounded classification. Only fixed categories and flags leave this class. */
final class Detector
{
    public const VERSION = 1;
    public const INTRODUCTION = 1;
    public const NAMED_UA = 2;
    public const TOOL = 4;
    public const HEADLESS = 8;
    public const MISSING_HEADERS = 16;
    public const NO_BROTLI = 32;
    public const RESEARCH_NETWORK = 64;
    public const RESEARCH_UA = 128;
    public const MUSE_RULE_EXPIRES = '2027-01-15';
    public const SOURCE = 'https://loosemore.com/2026/10/09/how-agents-show-up-what-muse-and-other-agents-reveal-when-they-use-whenisbins/';

    public static function categories(): array
    {
        return [
            'possible_muse' => ['Possibly Muse', 'A resemblance, not a revelation. A dated research clue matches alongside signs of automation.'],
            'possible_automation' => ['Something automated?', 'A browser with a few unusual habits. Privacy tools, proxies and ordinary software can look like this too.'],
            'tool' => ['A tool walked in', 'An HTTP library or headless browser. Could be an assistant, a monitor, a developer or a scraper.'],
            'declared_muse' => ['Says it is Muse', 'A self-introduction. We have not checked its ID.'],
            'declared_dot' => ['Says it is Dot / Dots', 'A self-introduction. No behavioural fingerprint is available here. DotBot is not treated as Dot.'],
            'declared_grok' => ['Says it is Grok', 'A self-introduction. No behavioural fingerprint is available here.'],
            'declared_other' => ['Introduced itself', 'Names an agent in X-Agent or carries a recognised agent product token. The claim is unverified.'],
        ];
    }

    public static function clues(int $flags): array
    {
        $labels = [
            self::INTRODUCTION => 'Sent an X-Agent self-introduction',
            self::NAMED_UA => 'User-Agent contains an agent product name',
            self::TOOL => 'User-Agent names an HTTP tool',
            self::HEADLESS => 'User-Agent names HeadlessChrome',
            self::MISSING_HEADERS => 'Claims Chrome but lacks both Fetch Metadata and client hints',
            self::NO_BROTLI => 'HTTPS Chrome request does not advertise Brotli',
            self::RESEARCH_NETWORK => 'Connection address matches the October 2026 research pool (shared and unverified)',
            self::RESEARCH_UA => 'Matches the Linux Chrome 138 fetcher string observed in the companion research',
        ];
        return array_values(array_filter($labels, static fn(int $bit): bool => (bool) ($flags & $bit), ARRAY_FILTER_USE_KEY));
    }

    /** @return array{category: string, clues: int, rule_version: int}|null */
    public function inspect(array $server, bool $https, string $utcDay): ?array
    {
        $ua = self::header($server, 'HTTP_USER_AGENT');
        $introduction = trim(self::header($server, 'HTTP_X_AGENT'));
        $names = ['muse' => 'muse', 'dot' => 'dot', 'dots' => 'dot', 'grok' => 'grok', 'grokbot' => 'grok'];

        // Arbitrary header values never become database labels or admin output.
        if ($introduction !== '') {
            $name = strtolower((string) preg_split('~[/\s]~', $introduction, 2)[0]);
            return self::result(isset($names[$name]) ? 'declared_' . $names[$name] : 'declared_other', self::INTRODUCTION);
        }
        foreach ($names as $token => $name) {
            if (preg_match('~(?:^|[\s;(])' . preg_quote($token, '~') . '(?:/|[\s;)]|$)~i', $ua)) {
                return self::result('declared_' . $name, self::NAMED_UA);
            }
        }
        if (preg_match('~(?:^|[\s;(])(?:ChatGPT-User|GPTBot|OAI-SearchBot|Claude-User|ClaudeBot|Claude-SearchBot|PerplexityBot|Perplexity-User|Google-Agent|meta-externalagent|meta-externalfetcher)(?:/|[\s;)]|$)~i', $ua)) {
            return self::result('declared_other', self::NAMED_UA);
        }

        $flags = 0;
        if (preg_match('~^(?:curl|Wget|python-requests|python-httpx|Python-urllib|undici|Go-http-client)(?:/|\s|$)~i', $ua)) {
            $flags |= self::TOOL;
        }
        if (preg_match('~\bHeadlessChrome/\d~i', $ua)) {
            $flags |= self::HEADLESS;
        }
        $chrome = (bool) preg_match('~\bChrome/\d~', $ua);
        // Related missing headers count as ONE clue, not several independent votes.
        if ($chrome && self::header($server, 'HTTP_SEC_FETCH_MODE') === ''
            && self::header($server, 'HTTP_SEC_FETCH_SITE') === ''
            && self::header($server, 'HTTP_SEC_FETCH_DEST') === ''
            && self::header($server, 'HTTP_SEC_CH_UA') === '') {
            $flags |= self::MISSING_HEADERS;
        }
        if ($chrome && $https && !preg_match('~(?:^|,)\s*br\s*(?:;|,|$)~i', self::header($server, 'HTTP_ACCEPT_ENCODING'))) {
            $flags |= self::NO_BROTLI;
        }
        $fingerprint = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36';
        $automation = (bool) ($flags & (self::TOOL | self::HEADLESS))
            || (($flags & (self::MISSING_HEADERS | self::NO_BROTLI)) === (self::MISSING_HEADERS | self::NO_BROTLI));
        if (!$automation) {
            return null;
        }
        // Never trust forwarding headers supplied by a visitor. A trusted host must
        // restore REMOTE_ADDR itself. Network membership alone never triggers a hit.
        if ($utcDay >= '2026-10-09' && $utcDay < self::MUSE_RULE_EXPIRES
            && self::inResearchNetwork(self::header($server, 'REMOTE_ADDR'))
            && ($ua === 'curl/8.5.0' || $ua === $fingerprint)) {
            $flags |= self::RESEARCH_NETWORK;
            if ($ua === $fingerprint) {
                $flags |= self::RESEARCH_UA;
            }
            return self::result('possible_muse', $flags);
        }
        return self::result(($flags & (self::TOOL | self::HEADLESS)) ? 'tool' : 'possible_automation', $flags);
    }

    private static function header(array $server, string $key): string
    {
        return isset($server[$key]) && is_string($server[$key]) ? substr($server[$key], 0, 2048) : '';
    }

    private static function inResearchNetwork(string $ip): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }
        // IPv4-mapped IPv6 is the same address, not a separate identity.
        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $packed = substr($packed, 12);
        }
        return strlen($packed) === 4 && ord($packed[0]) === 87
            && ord($packed[1]) === 81 && (ord($packed[2]) & 224) === 224;
    }

    private static function result(string $category, int $clues): array
    {
        return ['category' => $category, 'clues' => $clues, 'rule_version' => self::VERSION];
    }
}
