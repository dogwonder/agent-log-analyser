# agent-log-analyser

Finds AI agents and other automated clients in web server logs, including those that send a browser User-Agent.

It's a companion to [Markdown for Agents and Statistics](../markdown-for-agents-and-statistics). That plugin only counts requests that ask for Markdown. Agents that fetch the HTML page with a browser User-Agent never reach its statistics. This tool finds them in the host's access logs instead.

The Python analyser runs **offline, on your own machine, against a log export**. Nothing is installed on the site, nothing runs per request, and nothing is written to the site's database. It works the same for WordPress, Wagtail or any other site with an nginx-style log.

For an experimental live WordPress companion, see [Is this an agent?](wordpress/is-this-an-agent/README.md). It adds a playful admin notebook of uncertain HTML-request sightings with aggregate-only storage.

## Background

In October 2026, a manual analysis of worldcitiescultureforum.com found a fetcher that is very probably Muse. It read the site 18 times in a week, including a daily check of one page, and the plugin's stats never saw it. See `docs/research/2026-10-muse-agent-findings.md` in the plugin repo. This tool automates that analysis. Its acceptance test is finding that cluster without being told about it.

## Requirements

Python 3.11 or later, with no third-party packages.

## Usage

```bash
# Once, and again every few weeks: download operators' published IP ranges into ./ranges
PYTHONPATH=src python3 -m agent_log_analyser fetch-ranges

# Analyse a log export (wp.cloud / WordPress.com dashboard CSV, or combined-format logs, .gz OK)
PYTHONPATH=src python3 -m agent_log_analyser analyse ~/Desktop/export.csv --out reports/site-2026-10.md
```

To install it as a command, run `uv tool install .` (or `pipx install .`), then use `agent-log-analyser analyse …`.

Options for `analyse`:

| Option | Default | Purpose |
|---|---|---|
| `--format` | `auto` | `wpcloud-csv` or `combined` if auto-detection fails |
| `--ranges DIR` | `ranges` | Where `fetch-ranges` saved the published lists |
| `--clusters FILE` | none | Extra known clusters, same shape as `data/known_clusters.json` |
| `--min-requests N` | 5 | Smallest User-Agent group to flag |
| `--schedule-window MIN` | 30 | Time-of-day window for spotting daily fetches |
| `--top N` | 15 | Rows per report section |
| `--out FILE` | stdout | Write the Markdown report to a file |

### Getting a log export

- **wp.cloud / WordPress.com hosting:** export the web server log for the period from the hosting dashboard. Raw logs aren't available over SSH. If the row count is a round number, the export may be capped; export one day at a time instead.
- **Other hosts:** use the nginx or Apache access logs in the default "combined" format.

## What the report shows

| Section | What it means |
|---|---|
| **Probable automated fetchers** | Browser-like User-Agents whose IPs never load assets, claiming a Chrome version at least 8 behind what real visitors use, plus rotating IPs or response sizes a real browser wouldn't get. This is how the Muse cluster stands out. |
| **Rotating-IP clients** | Current-looking browsers with a new IP for almost every request, no referrer and no assets. These fit scrapers on residential proxies, but also privacy relays and real people, so treat them as leads only. |
| **Scheduled fetches** | The same page fetched by the same undeclared client in one time-of-day window on several days, such as a user's agent checking a page every morning. |
| **Undeclared tools and other clients** | HTTP libraries (`curl`, `python-httpx` …), headless browsers and unrecognised products that don't name themselves as bots. |
| **Declared agents** | Clients that name themselves as bots. *Verified* is the share of requests from that operator's published IP ranges, so a low value means some requests only claim the name. |
| **Browser-like requests from published operator ranges** | A browser User-Agent from a crawler operator's network: an agent that doesn't announce itself. |

### Signals, and how much to trust them

- **Never loads assets** gates every browser-like cluster but never decides on its own. The report header shows how many current-browser IPs load assets on this host. On WCCF it was only 23%, because real visitors' assets mostly come from browser caches or another domain.
- **Out-of-date browser:** the "current" Chrome version is worked out from visitors who load assets. Fetchers often ship a fixed User-Agent that falls years behind.
- **Response size:** compared with the median size real visitors receive for the same page. Fetchers without Brotli support get about 1.25x larger gzip responses.
- **Rotating IPs:** distinct IPs ÷ requests of 0.6 or more for one exact User-Agent.
- **Known clusters** (`data/known_clusters.json`) and **published ranges** only *label* results. They are never used to find them.

## Limits

- **Attribution is by fingerprint, not proof.** A network tied to an agent by outside evidence may be shared by other services.
- **One exact User-Agent per group.** A fetcher using today's most common Chrome string blends in with real visitors.
- **Request headers aren't in host logs.** The strongest live check, missing `Sec-Fetch-*` / `sec-ch-ua` headers from a client claiming to be Chrome, needs code running on the site. That's a possible Phase 2, to build only for rules this tool shows to be reliable.
- **The output depends on the log.** Requests a CDN answers before the origin may be missing.

## Privacy

Access logs contain IP addresses, which are personal data under UK GDPR.

- Reports never include full IPs: networks are shown as IPv4 /16 or IPv6 /32 groups.
- Keep exports and reports out of git. `.gitignore` excludes `*.csv`, `*.log`, `*.gz`, `reports/` and `ranges/`.
- Delete log exports after analysis.

## Development

### Experimental WordPress companion

[Is this an agent?](wordpress/is-this-an-agent/README.md) is a separate, installable
WordPress plugin for tentative live HTML request sightings. It offers a playful
admin field guide, explains every guess and stores only site-wide daily counters,
with no saved IPs or visitor identifiers. Observation starts paused, with seven
days of retention. It does not change the offline analyser below.

Build its ZIP with `python3 wordpress/build.py`; run its detector checks with
`php wordpress/tests/detector.php`. See its README for privacy controls and cache
limitations.

### Offline analyser

```bash
PYTHONPATH=src:tests python3 -m unittest discover -s tests
```

Layout:

- `readers.py`: log formats → `Request`
- `networks.py`: published ranges, known clusters, IP truncation
- `detectors.py`: classification, clustering, schedules, verification
- `report.py`: Markdown output
- `cli.py`: the command-line interface
