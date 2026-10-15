from datetime import UTC, datetime, timedelta

from agent_log_analyser.readers import Request

CURRENT_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
STALE_LINUX_CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"

START = datetime(2026, 10, 7, tzinfo=UTC)


def request(ip, path="/page/", ua=CURRENT_CHROME, at=None, size=28000, referer="", status=200, asset=False):
    return Request(
        ts=at or START,
        ip=ip,
        method="GET",
        path=path,
        status=status,
        bytes=size,
        ua=ua,
        referer=referer,
        is_asset=asset,
    )


def human_traffic(visitors=30):
    """Visitors on current Chrome who load the page and its assets."""
    rows = []
    for i in range(visitors):
        ip = f"203.0.{i // 200}.{i % 200 + 1}"
        at = START + timedelta(hours=i)
        rows.append(request(ip, "/page/", at=at, referer="https://example.org/"))
        rows.append(request(ip, "/wp-content/themes/x/app.css", at=at, size=5000, asset=True))
    return rows


def muse_like_fetcher(days=6, extra_paths=("/a/", "/b/", "/c/")):
    """A stale Chrome UA rotating through one block, never loading assets, daily at 10:40."""
    rows = []
    n = 0
    for day in range(days):
        n += 1
        at = START + timedelta(days=day, hours=10, minutes=35 + day)
        rows.append(request(f"87.81.{224 + n}.{n}", "/page/", ua=STALE_LINUX_CHROME, at=at, size=34920))
    for path in extra_paths:
        n += 1
        rows.append(request(f"87.81.{224 + n}.{n}", path, ua=STALE_LINUX_CHROME, at=START + timedelta(hours=n)))
    return rows
