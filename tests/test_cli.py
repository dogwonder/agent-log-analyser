import json
import os
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from agent_log_analyser.cli import main

from helpers import human_traffic, muse_like_fetcher


def combined_line(r):
    ts = r.ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    referer = r.referer or "-"
    return f'{r.ip} - - [{ts}] "{r.method} {r.path} HTTP/1.1" {r.status} {r.bytes} "{referer}" "{r.ua}"\n'


class AnalyseCommandTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: [p.unlink() for p in self.dir.rglob("*") if p.is_file()])
        self.rows = human_traffic() + muse_like_fetcher()
        self.log = self.dir / "access.log"
        self.log.write_text("".join(combined_line(r) for r in self.rows))
        self.report = self.dir / "report.md"

    def run_analyse(self, *extra):
        with redirect_stderr(StringIO()):
            code = main(["analyse", str(self.log), "--out", str(self.report), *extra])
        self.assertEqual(0, code)
        return self.report.read_text()

    def test_missing_log_file_is_a_clean_error(self):
        stderr = StringIO()
        with redirect_stderr(stderr):
            code = main(["analyse", str(self.dir / "nope.csv")])
        self.assertEqual(2, code)
        self.assertIn("Log file not found", stderr.getvalue())

    def test_report_finds_and_labels_the_fetcher(self):
        text = self.run_analyse("--ranges", str(self.dir / "no-ranges"))

        self.assertIn("## Probable automated fetchers", text)
        self.assertIn("Chrome/138.0.0.0", text)
        self.assertIn("Muse (probable)", text)
        self.assertIn("## Scheduled fetches", text)
        self.assertIn("not loaded (run fetch-ranges)", text)

    def test_report_never_contains_full_ips(self):
        text = self.run_analyse("--ranges", str(self.dir / "no-ranges"))

        for ip in {r.ip for r in self.rows}:
            self.assertNotIn(ip, text)

    def test_report_shows_ranges_fetch_date_and_warns_when_stale(self):
        ranges = self.dir / "ranges"
        ranges.mkdir()
        listing = ranges / "openai-gptbot.json"
        listing.write_text(json.dumps({"prefixes": [{"ipv4Prefix": "20.171.0.0/16"}]}))
        stale = time.mktime((2026, 6, 1, 12, 0, 0, 0, 0, -1))
        os.utime(listing, (stale, stale))

        text = self.run_analyse("--ranges", str(ranges))

        self.assertIn("loaded (fetched 01 Jun 2026)", text)
        self.assertIn("refetch before trusting Verified", text)


if __name__ == "__main__":
    unittest.main()
