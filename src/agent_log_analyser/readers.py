"""Read web server logs into one common request shape.

Two formats are supported:

- ``wpcloud-csv``: the WordPress.com / wp.cloud dashboard export (nginx_json
  rows as CSV, with ``user_ip``, ``http_user_agent``, ``renderer`` …).
- ``combined``: the nginx / Apache "combined" access log format.

Files ending ``.gz`` are decompressed transparently.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ASSET_PATH = re.compile(
    r"\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm|mp3)(?:\?|$)",
    re.IGNORECASE,
)

COMBINED_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


@dataclass(frozen=True, slots=True)
class Request:
    """One logged request, reduced to the fields the analysis needs."""

    ts: datetime
    ip: str
    method: str
    path: str
    status: int
    bytes: int
    ua: str
    referer: str
    is_asset: bool


def _open_text(path: Path) -> io.TextIOBase:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path), encoding="utf-8", errors="replace", newline="")
    return path.open(encoding="utf-8", errors="replace", newline="")


def detect_format(path: Path) -> str:
    """Return ``wpcloud-csv`` or ``combined`` from the file's first line."""
    with _open_text(path) as handle:
        first = handle.readline()
    if "http_user_agent" in first and "user_ip" in first:
        return "wpcloud-csv"
    if COMBINED_LINE.match(first):
        return "combined"
    raise ValueError(f"Unrecognised log format in {path}; pass --format explicitly.")


def read_requests(path: Path, fmt: str = "auto") -> Iterator[Request]:
    """Yield requests from ``path``; unparseable lines are skipped."""
    if fmt == "auto":
        fmt = detect_format(path)
    if fmt == "wpcloud-csv":
        yield from _read_wpcloud_csv(path)
    elif fmt == "combined":
        yield from _read_combined(path)
    else:
        raise ValueError(f"Unknown format {fmt!r}")


def _client_ip(user_ip: str, forwarded_for: str) -> str:
    if user_ip:
        return user_ip.strip()
    return forwarded_for.split(",")[0].strip()


def _int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _read_wpcloud_csv(path: Path) -> Iterator[Request]:
    with _open_text(path) as handle:
        for row in csv.DictReader(handle):
            try:
                ts = datetime.fromisoformat(row["date"].replace("Z", "+00:00"))
            except (KeyError, ValueError):
                continue
            url = row.get("request_url", "")
            yield Request(
                ts=ts,
                ip=_client_ip(row.get("user_ip", ""), row.get("http_x_forwarded_for", "")),
                method=row.get("request_type", ""),
                path=url,
                status=_int(row.get("status", "")),
                bytes=_int(row.get("body_bytes_sent", "")),
                ua=row.get("http_user_agent", ""),
                referer=row.get("http_referer", ""),
                is_asset=row.get("renderer") == "static" or bool(ASSET_PATH.search(url)),
            )


def _read_combined(path: Path) -> Iterator[Request]:
    with _open_text(path) as handle:
        for line in handle:
            match = COMBINED_LINE.match(line)
            if not match:
                continue
            try:
                ts = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                continue
            url = match["path"]
            yield Request(
                ts=ts,
                ip=match["ip"],
                method=match["method"],
                path=url,
                status=int(match["status"]),
                bytes=_int(match["bytes"]),
                ua=match["ua"],
                referer="" if match["referer"] == "-" else match["referer"],
                is_asset=bool(ASSET_PATH.search(url)),
            )
