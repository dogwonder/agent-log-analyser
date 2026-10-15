"""Find agent traffic in a set of requests.

Detection never depends on known networks. Browser-like requests are grouped by
exact User-Agent, and a group is flagged on behaviour: its IPs never load page
assets, plus at least one of rotating IPs, an out-of-date browser version or
unusual response sizes. Known clusters and published ranges only *label*
groups afterwards.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, timedelta

from .networks import NamedRanges, network_label
from .readers import Request

TOOL_UA = re.compile(
    r"^(?:curl|wget|python|aiohttp|httpx|go-http-client|java|okhttp|axios|node|undici|libwww|scrapy|"
    r"ruby|php|guzzlehttp|apache-httpclient|dart|reqwest|deno|bun)\b|headlesschrome|phantomjs|puppeteer|playwright",
    re.IGNORECASE,
)
# Bot words, a "compatible; Name/1.0" product token (the classic bot form;
# MSIE's "compatible; MSIE 9.0" has no slash) or a contact URL.
DECLARED_UA = re.compile(
    r"bot\b|bot/|crawler|spider|scraper|slurp|fetcher|externalhit|archiver|-user/|compatible;\s*[^;)\s]+/\d|\+https?://",
    re.IGNORECASE,
)
# Includes bare AppleWebKit/Gecko/Trident so in-app browsers (no "Safari/") count as browsers.
BROWSER_UA = re.compile(r"^Mozilla/\d.*(?:Chrome|Firefox|Safari|Edg|AppleWebKit|Gecko|Trident)/", re.IGNORECASE)
CHROME_MAJOR = re.compile(r"Chrome/(\d+)")
NON_PAGE_PATH = re.compile(
    r"^/(?:wp-admin|wp-login\.php|wp-cron\.php|xmlrpc\.php|wp-json|favicon\.ico|robots\.txt|.*sitemap.*\.xml)",
    re.IGNORECASE,
)


def classify_ua(ua: str) -> str:
    """Return ``tool``, ``declared``, ``browser`` or ``other``."""
    if not ua.strip() or TOOL_UA.search(ua):
        return "tool"
    if DECLARED_UA.search(ua):
        return "declared"
    if BROWSER_UA.match(ua):
        return "browser"
    return "other"


def agent_name(ua: str) -> str:
    """A stable product name for a declared agent, without its version."""
    match = re.search(r"compatible;\s*([^/;()\s]+)/", ua, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"([\w.-]*(?:bot|crawler|spider|scraper|fetcher|-User))/", ua, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.match(r"([^/\s;(]+)", ua)
    return match.group(1) if match else ua[:40]


def is_page_request(request: Request) -> bool:
    return (
        not request.is_asset
        and request.method in ("GET", "HEAD")
        and request.status in (200, 304)
        and not NON_PAGE_PATH.match(request.path)
    )


@dataclass
class Cluster:
    """Page requests sharing one exact User-Agent."""

    ua: str
    kind: str
    requests: list[Request] = field(default_factory=list)
    headless_share: float = 0.0
    referer_share: float = 0.0
    chrome_major: int | None = None
    staleness: int | None = None
    size_ratio: float | None = None
    flags: list[str] = field(default_factory=list)
    labels: Counter = field(default_factory=Counter)

    @property
    def ips(self) -> set[str]:
        return {r.ip for r in self.requests}

    @property
    def networks(self) -> Counter:
        return Counter(network_label(r.ip) for r in self.requests)

    @property
    def top_paths(self) -> Counter:
        return Counter(r.path for r in self.requests)


@dataclass
class Schedule:
    ua: str
    path: str
    window_start: int  # minutes after midnight UTC
    window_minutes: int
    days: list[date]
    requests: int


@dataclass
class DeclaredAgent:
    name: str
    requests: int
    ips: int
    verified_share: float | None  # None when no published ranges cover this agent


@dataclass
class Analysis:
    total_requests: int
    page_requests: int
    start: object
    end: object
    modal_chrome: int | None
    fetchers: list[Cluster]
    rotators: list[Cluster]
    tools: list[Cluster]
    asset_baseline: float | None
    declared: list[DeclaredAgent]
    schedules: list[Schedule]
    range_browser_hits: Counter
    ranges_loaded: bool


def _label(cluster: Cluster, labellers: list[NamedRanges]) -> None:
    for request in cluster.requests:
        for ranges in labellers:
            if ranges.contains(request.ip):
                cluster.labels[ranges.label] += 1


def find_schedules(
    requests: Iterable[Request], window_minutes: int = 30, min_days: int = 4
) -> list[Schedule]:
    """Find (User-Agent, path) pairs fetched in the same time-of-day window on many days."""
    by_key: dict[tuple[str, str], list[Request]] = defaultdict(list)
    for request in requests:
        by_key[(request.ua, request.path)].append(request)

    found = []
    for (ua, path), group in by_key.items():
        if len(group) < min_days:
            continue
        all_days = {r.ts.date() for r in group}
        points = sorted((r.ts.hour * 60 + r.ts.minute, r.ts.date()) for r in group)
        # Duplicate with +1440 so a window can wrap past midnight; a wrapped
        # point belongs to the previous day's run.
        wrapped = points + [(minute + 1440, day - timedelta(days=1)) for minute, day in points]
        best_days: set[date] = set()
        best_start = 0
        best_count = 0
        for i, (start, _) in enumerate(points):
            in_window = [day for minute, day in wrapped[i:] if minute - start <= window_minutes]
            days = set(in_window)
            if len(days) > len(best_days):
                best_days, best_start, best_count = days, start, len(in_window)
        if len(best_days) >= min_days and len(best_days) >= len(all_days) / 2:
            found.append(Schedule(ua, path, best_start % 1440, window_minutes, sorted(best_days), best_count))
    return sorted(found, key=lambda s: (-len(s.days), -s.requests))


def analyse(
    requests: Iterable[Request],
    published: list[NamedRanges] | None = None,
    known: list[NamedRanges] | None = None,
    min_requests: int = 5,
    schedule_window: int = 30,
) -> Analysis:
    published = published or []
    known = known or []
    rows = list(requests)
    pages = [r for r in rows if is_page_request(r)]
    asset_ips = {r.ip for r in rows if r.is_asset}

    # Real browsers: IPs that loaded assets give the "current" Chrome version
    # and the normal response size for each page.
    human_pages = [r for r in pages if r.ip in asset_ips and classify_ua(r.ua) == "browser"]
    majors = Counter(int(m.group(1)) for r in human_pages if (m := CHROME_MAJOR.search(r.ua)))
    modal_chrome = majors.most_common(1)[0][0] if majors else None
    # How often do current-browser visitors' IPs load assets at all? Reported so
    # the reader can judge the "never loads assets" signal on this host.
    current_ips = {
        r.ip
        for r in pages
        if classify_ua(r.ua) == "browser"
        and modal_chrome is not None
        and (m := CHROME_MAJOR.search(r.ua))
        and int(m.group(1)) >= modal_chrome - 4
    }
    asset_baseline = sum(ip in asset_ips for ip in current_ips) / len(current_ips) if current_ips else None
    sizes: dict[str, list[int]] = defaultdict(list)
    for r in human_pages:
        if r.status == 200 and r.bytes:
            sizes[r.path].append(r.bytes)
    baseline = {path: statistics.median(v) for path, v in sizes.items() if len(v) >= 5}

    clusters: dict[str, Cluster] = {}
    for r in pages:
        kind = classify_ua(r.ua)
        if kind == "declared":
            continue
        clusters.setdefault(r.ua, Cluster(r.ua, kind)).requests.append(r)

    fetchers, rotators, tools = [], [], []
    for cluster in clusters.values():
        reqs = cluster.requests
        ips = cluster.ips
        cluster.headless_share = sum(ip not in asset_ips for ip in ips) / len(ips)
        cluster.referer_share = sum(bool(r.referer) for r in reqs) / len(reqs)
        ratios = [r.bytes / baseline[r.path] for r in reqs if r.path in baseline and r.status == 200 and r.bytes]
        cluster.size_ratio = statistics.median(ratios) if ratios else None
        if match := CHROME_MAJOR.search(cluster.ua):
            cluster.chrome_major = int(match.group(1))
            if modal_chrome is not None:
                cluster.staleness = modal_chrome - cluster.chrome_major

        if cluster.kind != "browser":
            _label(cluster, known + published)
            tools.append(cluster)
            continue
        if len(reqs) < min_requests or cluster.headless_share < 0.9:
            continue

        rotating = len(ips) / len(reqs) >= 0.6
        stale = cluster.staleness is not None and cluster.staleness >= 8
        odd_size = cluster.size_ratio is not None and not 0.85 <= cluster.size_ratio <= 1.15
        cluster.flags.append("never loads assets")
        if rotating:
            cluster.flags.append(f"rotating IPs ({len(ips)} for {len(reqs)} requests)")
        if stale:
            cluster.flags.append(f"browser {cluster.staleness} versions out of date")
        if odd_size:
            cluster.flags.append(f"response size x{cluster.size_ratio:.2f} of normal")
        if cluster.referer_share <= 0.1:
            cluster.flags.append("no referrer")

        # Asset loading is a weak signal on hosts where real visitors' assets come
        # from browser caches or another domain, so it gates but never decides.
        # A browser version real visitors left behind, plus rotation or a response
        # a real browser would not get, marks a fetcher. Rotation alone fits
        # residential proxies and privacy relays too, so it is reported apart.
        if stale and (rotating or odd_size):
            _label(cluster, known + published)
            fetchers.append(cluster)
        elif rotating and cluster.referer_share <= 0.1:
            _label(cluster, known + published)
            rotators.append(cluster)

    fetchers.sort(key=lambda c: (-len(c.flags), -len(c.requests)))
    rotators.sort(key=lambda c: -len(c.requests))
    tools.sort(key=lambda c: -len(c.requests))

    declared_groups: dict[str, list[Request]] = defaultdict(list)
    for r in pages:
        if classify_ua(r.ua) == "declared":
            declared_groups[agent_name(r.ua)].append(r)
    declared = []
    for name, reqs in declared_groups.items():
        covering = [p for p in published if any(t.lower() == name.lower() for t in p.tokens)]
        verified = (
            sum(any(p.contains(r.ip) for p in covering) for r in reqs) / len(reqs) if covering else None
        )
        declared.append(DeclaredAgent(name, len(reqs), len({r.ip for r in reqs}), verified))
    declared.sort(key=lambda d: -d.requests)

    undeclared = [r for r in pages if classify_ua(r.ua) != "declared" and r.ip not in asset_ips]
    schedules = find_schedules(undeclared, window_minutes=schedule_window)

    range_hits: Counter = Counter()
    for r in pages:
        if classify_ua(r.ua) == "browser":
            for ranges in published:
                if ranges.contains(r.ip):
                    range_hits[(ranges.label, r.ua)] += 1

    return Analysis(
        total_requests=len(rows),
        page_requests=len(pages),
        start=min((r.ts for r in rows), default=None),
        end=max((r.ts for r in rows), default=None),
        modal_chrome=modal_chrome,
        fetchers=fetchers,
        rotators=rotators,
        tools=tools,
        asset_baseline=asset_baseline,
        declared=declared,
        schedules=schedules,
        range_browser_hits=range_hits,
        ranges_loaded=bool(published),
    )
