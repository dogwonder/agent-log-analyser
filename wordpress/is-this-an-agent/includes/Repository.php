<?php

declare(strict_types=1);

namespace ChanceryLane\AgentFinder;

/** Site-wide daily counters: no IP, hash, raw header, URL, post ID or visitor ID. */
final class Repository
{
    private string $table;

    public function __construct(private readonly \wpdb $db)
    {
        $this->table = $db->prefix . 'itia_daily';
    }

    public function install(): void
    {
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $collation = $this->db->get_charset_collate();
        dbDelta("CREATE TABLE {$this->table} (
            observed_day date NOT NULL,
            category varchar(32) NOT NULL,
            clues smallint unsigned NOT NULL,
            rule_version smallint unsigned NOT NULL,
            hits bigint unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (observed_day,category,clues,rule_version)
        ) $collation;");
    }

    public function record(array $finding, string $day): void
    {
        if (!isset(Detector::categories()[$finding['category'] ?? ''])
            || !is_int($finding['clues'] ?? null) || $finding['clues'] < 1 || ($finding['clues'] & ~Detector::ALL_CLUES) !== 0
            || ($finding['rule_version'] ?? null) !== Detector::VERSION
            || !preg_match('/^\d{4}-\d{2}-\d{2}$/D', $day)) {
            return;
        }
        $this->db->query($this->db->prepare(
            "INSERT INTO {$this->table} (observed_day,category,clues,rule_version,hits)
             VALUES (%s,%s,%d,%d,1) ON DUPLICATE KEY UPDATE hits = hits + 1",
            $day, $finding['category'], $finding['clues'], $finding['rule_version']
        ));
    }

    public static function cutoff(int $days, ?int $now = null): string
    {
        return gmdate('Y-m-d', ($now ?? time()) - (max(1, min(30, $days)) - 1) * DAY_IN_SECONDS);
    }

    public function prune(int $days): void
    {
        $this->db->query($this->db->prepare("DELETE FROM {$this->table} WHERE observed_day < %s", self::cutoff($days)));
    }

    public function rows(int $days): array
    {
        return $this->db->get_results($this->db->prepare(
            "SELECT observed_day, category, clues, rule_version, hits FROM {$this->table}
             WHERE observed_day >= %s ORDER BY observed_day DESC, hits DESC LIMIT 200",
            self::cutoff($days)
        ), ARRAY_A) ?: [];
    }

    public function totals(int $days): array
    {
        $rows = $this->db->get_results($this->db->prepare(
            "SELECT category, SUM(hits) AS hits FROM {$this->table}
             WHERE observed_day >= %s GROUP BY category", self::cutoff($days)
        ), ARRAY_A) ?: [];
        return array_column($rows, 'hits', 'category');
    }

    public function clear(): void
    {
        $this->db->query("DELETE FROM {$this->table}");
    }
}
