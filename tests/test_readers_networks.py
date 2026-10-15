import ipaddress
import tempfile
import unittest
from pathlib import Path

from agent_log_analyser.networks import NamedRanges, load_known_clusters, prefixes_from_json, truncate_ip
from agent_log_analyser.readers import detect_format, read_requests

WPCLOUD = (
    '"date","request_completion","request_time","request_type","body_bytes_sent","cached","user_ip","http_host",'
    '"http_x_forwarded_for","http_user_agent","http_referer","http_version","http2","scheme","status","timestamp",'
    '"renderer","request_url","type"\n'
    '"2026-10-07T10:44:29.956Z","OK","0.8","GET","34920","false","87.81.226.121","example.org","87.81.226.121",'
    '"Mozilla/5.0 (X11; Linux x86_64) Chrome/138.0.0.0 Safari/537.36","","HTTP/1.1","","https","200","1",'
    '"php","/2026/03/04/tokyo/","nginx_json"\n'
    '"2026-10-07T10:44:30.000Z","OK","0","GET","5000","false","203.0.113.5","example.org","203.0.113.5",'
    '"Mozilla/5.0 Chrome/154.0.0.0","https://example.org/","HTTP/1.1","","https","200","1",'
    '"static","/wp-content/themes/x/font.woff2","nginx_json"\n'
)

COMBINED = (
    '87.81.226.121 - - [07/Oct/2026:10:44:29 +0000] "GET /tokyo/?output_format=md HTTP/1.1" 200 5807 "-" '
    '"Mozilla/5.0 (X11; Linux x86_64) Chrome/138.0.0.0 Safari/537.36"\n'
    "not a log line\n"
    '203.0.113.5 - - [07/Oct/2026:10:44:30 +0000] "GET /app.css HTTP/1.1" 200 5000 "https://example.org/" "Mozilla/5.0"\n'
)


class ReadersTest(unittest.TestCase):
    def write(self, text, suffix):
        handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
        handle.write(text)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return Path(handle.name)

    def test_wpcloud_csv(self):
        path = self.write(WPCLOUD, ".csv")
        self.assertEqual("wpcloud-csv", detect_format(path))
        rows = list(read_requests(path))

        self.assertEqual(2, len(rows))
        self.assertEqual("87.81.226.121", rows[0].ip)
        self.assertEqual(34920, rows[0].bytes)
        self.assertFalse(rows[0].is_asset)
        self.assertTrue(rows[1].is_asset)
        self.assertEqual(10, rows[0].ts.hour)

    def test_combined_skips_bad_lines(self):
        path = self.write(COMBINED, ".log")
        self.assertEqual("combined", detect_format(path))
        rows = list(read_requests(path))

        self.assertEqual(2, len(rows))
        self.assertEqual("/tokyo/?output_format=md", rows[0].path)
        self.assertEqual("", rows[0].referer)
        self.assertTrue(rows[1].is_asset)


class NetworksTest(unittest.TestCase):
    def test_truncate_ip(self):
        self.assertEqual("87.81.226.x", truncate_ip("87.81.226.121"))
        self.assertEqual("2001:db8:1::/48", truncate_ip("2001:db8:1:2::5"))
        self.assertEqual("?", truncate_ip("not-an-ip"))

    def test_prefixes_from_published_json(self):
        payload = {"creationTime": "x", "prefixes": [{"ipv4Prefix": "66.249.64.0/27"}, {"ipv6Prefix": "2001:4860:4801::/64"}]}
        self.assertEqual(2, len(prefixes_from_json(payload)))

    def test_named_ranges_contains_mixed_versions(self):
        ranges = NamedRanges("k", "K", (ipaddress.ip_network("87.81.224.0/19"), ipaddress.ip_network("2001:db8::/32")))
        self.assertTrue(ranges.contains("87.81.255.255"))
        self.assertFalse(ranges.contains("87.82.0.1"))
        self.assertTrue(ranges.contains("2001:db8::1"))

    def test_bundled_known_clusters_include_muse(self):
        names = [c.label for c in load_known_clusters()]
        self.assertIn("Muse (probable)", names)


if __name__ == "__main__":
    unittest.main()
