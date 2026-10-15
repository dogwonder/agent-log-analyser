"""Render an Analysis as a Markdown report.

IPs never appear in full: networks are shown as IPv4 /16 or IPv6 /32 groups.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from .detectors import Analysis, Cluster


def _ua(ua: str, limit: int = 110) -> str:
    ua = ua.replace("|", "\\|").replace("`", "'")
    return f"`{ua[:limit]}{'…' if len(ua) > limit else ''}`" if ua else "*(empty)*"


def _networks(cluster: Cluster, limit: int = 3) -> str:
    top = cluster.networks.most_common(limit)
    more = len(cluster.networks) - len(top)
    text = ", ".join(f"{net} ({n})" for net, n in top)
    return text + (f", +{more} more" if more > 0 else "")


def _labels(cluster: Cluster) -> str:
    return ", ".join(f"{label} ({n})" for label, n in cluster.labels.most_common()) or "—"


def _hhmm(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


RANGES_MAX_AGE_DAYS = 30


def _ranges_line(analysis: Analysis, fetched: datetime | None) -> str:
    if not analysis.ranges_loaded:
        return "not loaded (run fetch-ranges)"
    if fetched is None or analysis.end is None:
        return "loaded"
    line = f"loaded (fetched {fetched:%d %b %Y})"
    # Operators change their lists; ranges far from the log period can misverify.
    gap = abs((analysis.end - fetched).days)
    if gap > RANGES_MAX_AGE_DAYS:
        line += f" — **{gap} days from the log period; refetch before trusting Verified**"
    return line


def render(analysis: Analysis, source_name: str, top: int = 15, ranges_fetched: datetime | None = None) -> str:
    a = analysis
    out: list[str] = []
    add = out.append

    add("# Agent log analysis\n")
    period = f"{a.start:%d %b %Y %H:%M} – {a.end:%d %b %Y %H:%M} UTC" if a.start else "empty log"
    add(f"**Source:** `{source_name}`  ")
    add(f"**Period:** {period}  ")
    add(f"**Requests:** {a.total_requests:,} ({a.page_requests:,} page requests)  ")
    add(f"**Current Chrome (from visitors loading assets):** {a.modal_chrome or 'unknown'}  ")
    if a.asset_baseline is not None:
        add(f"**Current-browser IPs that load assets:** {a.asset_baseline:.0%} (the lower this is, the weaker \"never loads assets\" is as a signal)  ")
    add(f"**Published IP ranges:** {_ranges_line(a, ranges_fetched)}\n")

    fetcher_requests = sum(len(c.requests) for c in a.fetchers)
    declared_requests = sum(d.requests for d in a.declared)
    add(
        f"**Summary:** {len(a.fetchers)} probable automated fetchers made {fetcher_requests:,} page requests, "
        f"against {declared_requests:,} from {len(a.declared)} declared agents. "
        f"{len(a.rotators)} rotating-IP clients made {sum(len(c.requests) for c in a.rotators):,} more (leads only). "
        f"{sum(a.range_browser_hits.values()):,} browser-like page requests came from published operator ranges.\n"
    )

    add("## Probable automated fetchers\n")
    add(
        "Browser-like User-Agents whose IPs never load page assets, claiming a browser version real visitors "
        "have left behind, plus rotating IPs or response sizes a real browser wouldn't get. "
        "Each row is one exact User-Agent string.\n"
    )
    if a.fetchers:
        add("| # | User-Agent | Page requests | IPs | Networks | Signals | Known networks |")
        add("|---|---|---|---|---|---|---|")
        for i, c in enumerate(a.fetchers[:top], 1):
            add(
                f"| {i} | {_ua(c.ua)} | {len(c.requests)} | {len(c.ips)} | {_networks(c)} "
                f"| {'; '.join(c.flags)} | {_labels(c)} |"
            )
        add("")
        for i, c in enumerate(a.fetchers[:top], 1):
            paths = ", ".join(f"`{p[:70]}` ({n})" for p, n in c.top_paths.most_common(3))
            add(f"- **#{i} top pages:** {paths}")
        add("")
    else:
        add("None found.\n")

    add("## Rotating-IP clients\n")
    add(
        "Current-looking browsers using a new IP for almost every request, with no referrer and no assets. "
        "This fits scrapers on residential proxies, but also privacy relays and real visitors, so treat as a lead only.\n"
    )
    if a.rotators:
        add("| User-Agent | Page requests | IPs | Networks | Known networks |")
        add("|---|---|---|---|---|")
        for c in a.rotators[:top]:
            add(f"| {_ua(c.ua, 80)} | {len(c.requests)} | {len(c.ips)} | {_networks(c, 2)} | {_labels(c)} |")
        add("")
    else:
        add("None found.\n")

    add("## Scheduled fetches\n")
    add(
        "Pages fetched by the same undeclared client in one time-of-day window on several days, "
        "one row per client.\n"
    )
    if a.schedules:
        by_ua: dict[str, list] = defaultdict(list)
        for s in a.schedules:
            by_ua[s.ua].append(s)
        add("| User-Agent | Pages on a schedule | Days | Example |")
        add("|---|---|---|---|")
        for ua, group in sorted(by_ua.items(), key=lambda item: -len(item[1]))[:top]:
            first = max(group, key=lambda s: (len(s.days), s.requests))
            window = f"{_hhmm(first.window_start)}–{_hhmm((first.window_start + first.window_minutes) % 1440)}"
            days = max(len(s.days) for s in group)
            add(f"| {_ua(ua, 80)} | {len(group)} | up to {days} | `{first.path[:60]}` daily {window} UTC |")
        add("")
    else:
        add("None found.\n")

    add("## Undeclared tools and other clients\n")
    add("HTTP libraries, headless browsers and unrecognised products that don't name themselves as bots.\n")
    if a.tools:
        add("| User-Agent | Page requests | IPs | Networks | Known networks |")
        add("|---|---|---|---|---|")
        for c in a.tools[:top]:
            add(f"| {_ua(c.ua, 80)} | {len(c.requests)} | {len(c.ips)} | {_networks(c, 2)} | {_labels(c)} |")
        add("")
    else:
        add("None found.\n")

    add("## Declared agents\n")
    add("Clients that name themselves as bots. *Verified* is the share of requests from that operator's published ranges.\n")
    if a.declared:
        add("| Agent | Page requests | IPs | Verified |")
        add("|---|---|---|---|")
        for d in a.declared[: top * 2]:
            verified = "not checked" if d.verified_share is None else f"{d.verified_share:.0%}"
            add(f"| {d.name} | {d.requests} | {d.ips} | {verified} |")
        add("")
    else:
        add("None found.\n")

    if a.range_browser_hits:
        add("## Browser-like requests from published operator ranges\n")
        add("A browser User-Agent from a crawler operator's network: an agent that doesn't announce itself.\n")
        per_range: dict[str, Counter] = defaultdict(Counter)
        for (label, ua), n in a.range_browser_hits.items():
            per_range[label][ua] += n
        add("| Range | Page requests | User-Agents | Most common |")
        add("|---|---|---|---|")
        for label, uas in sorted(per_range.items(), key=lambda item: -sum(item[1].values())):
            ua, n = uas.most_common(1)[0]
            add(f"| {label} | {sum(uas.values())} | {len(uas)} | {_ua(ua, 70)} ({n}) |")
        add("")

    add("---\n")
    add(
        "*Attribution is by fingerprint, not proof. Networks are shown as /16 (IPv4) or /32 (IPv6) groups; "
        "no full IP addresses are included. The input log contains personal data — delete it after analysis.*"
    )
    return "\n".join(out) + "\n"
