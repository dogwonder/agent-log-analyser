"""IP helpers: published operator ranges, known clusters and truncation."""

from __future__ import annotations

import bisect
import functools
import ipaddress
import json
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@functools.lru_cache(maxsize=65536)
def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def truncate_ip(value: str) -> str:
    """Drop the host part: IPv4 to /24 (``87.81.226.x``), IPv6 to /48."""
    ip = parse_ip(value)
    if ip is None:
        return "?"
    if ip.version == 4:
        return ".".join(str(ip).split(".")[:3]) + ".x"
    return str(ipaddress.ip_network(f"{ip}/48", strict=False))


def network_label(value: str) -> str:
    """Group key used to show where a cluster's traffic comes from (IPv4 /16, IPv6 /32)."""
    ip = parse_ip(value)
    if ip is None:
        return "?"
    prefix = 16 if ip.version == 4 else 32
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


@dataclass(frozen=True)
class NamedRanges:
    """A named set of networks, e.g. one operator's published list or a known cluster."""

    key: str
    label: str
    networks: tuple[Network, ...]
    tokens: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Merged, sorted integer intervals per IP version, searched with bisect.
        for version in (4, 6):
            spans = sorted(
                (int(net.network_address), int(net.broadcast_address))
                for net in self.networks
                if net.version == version
            )
            merged: list[list[int]] = []
            for start, end in spans:
                if merged and start <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            object.__setattr__(self, f"_starts{version}", [m[0] for m in merged])
            object.__setattr__(self, f"_ends{version}", [m[1] for m in merged])

    def contains(self, value: str) -> bool:
        ip = parse_ip(value)
        if ip is None:
            return False
        starts = getattr(self, f"_starts{ip.version}")
        index = bisect.bisect_right(starts, int(ip)) - 1
        return index >= 0 and int(ip) <= getattr(self, f"_ends{ip.version}")[index]


def _load_package_json(name: str) -> dict:
    return json.loads(files(__package__).joinpath("data", name).read_text())


def range_sources() -> dict[str, dict]:
    return _load_package_json("range_sources.json")["sources"]


def prefixes_from_json(payload: dict) -> list[Network]:
    """Collect ``ipv4Prefix`` / ``ipv6Prefix`` values from an operator's range list."""
    found: list[Network] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("ipv4Prefix", "ipv6Prefix") and isinstance(value, str):
                    try:
                        found.append(ipaddress.ip_network(value, strict=False))
                    except ValueError:
                        pass
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return found


def fetch_ranges(out_dir: Path, timeout: float = 20.0) -> dict[str, str]:
    """Download every published range list into ``out_dir``; return key → outcome."""
    out_dir.mkdir(parents=True, exist_ok=True)
    outcomes: dict[str, str] = {}
    for key, source in range_sources().items():
        try:
            request = urllib.request.Request(source["url"], headers={"User-Agent": "agent-log-analyser/0.1"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read())
            count = len(prefixes_from_json(payload))
            if count == 0:
                outcomes[key] = "no prefixes found (format changed?)"
                continue
            (out_dir / f"{key}.json").write_text(json.dumps(payload))
            outcomes[key] = f"{count} prefixes"
        except Exception as error:  # noqa: BLE001 — report every failure, keep going.
            outcomes[key] = f"failed: {error}"
    return outcomes


def load_published_ranges(ranges_dir: Path | None) -> list[NamedRanges]:
    """Load range lists previously saved by ``fetch_ranges``; missing files are skipped."""
    if ranges_dir is None or not ranges_dir.is_dir():
        return []
    loaded = []
    for key, source in range_sources().items():
        path = ranges_dir / f"{key}.json"
        if not path.is_file():
            continue
        networks = prefixes_from_json(json.loads(path.read_text()))
        if networks:
            loaded.append(
                NamedRanges(key, f"{source['operator']} ({key})", tuple(networks), tuple(source["tokens"]))
            )
    return loaded


def ranges_fetched_at(ranges_dir: Path | None) -> datetime | None:
    """When the oldest saved range list was fetched, from file modification times."""
    if ranges_dir is None or not ranges_dir.is_dir():
        return None
    times = [(ranges_dir / f"{key}.json").stat().st_mtime for key in range_sources() if (ranges_dir / f"{key}.json").is_file()]
    return datetime.fromtimestamp(min(times), tz=UTC) if times else None


def load_known_clusters(extra: Path | None = None) -> list[NamedRanges]:
    """Bundled known clusters, plus any from a user-supplied file of the same shape."""
    payloads = [_load_package_json("known_clusters.json")]
    if extra is not None:
        payloads.append(json.loads(extra.read_text()))
    clusters = []
    for payload in payloads:
        for row in payload.get("clusters", []):
            networks = tuple(ipaddress.ip_network(cidr, strict=False) for cidr in row["cidrs"])
            clusters.append(NamedRanges(row["name"], row["name"], networks))
    return clusters
