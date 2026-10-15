import ipaddress
import unittest
from datetime import timedelta

from agent_log_analyser.detectors import agent_name, analyse, classify_ua, find_schedules
from agent_log_analyser.networks import NamedRanges

from helpers import (
    CURRENT_CHROME,
    GPTBOT,
    START,
    STALE_LINUX_CHROME,
    human_traffic,
    muse_like_fetcher,
    request,
)


class ClassifyUaTest(unittest.TestCase):
    def test_browser(self):
        self.assertEqual("browser", classify_ua(CURRENT_CHROME))

    def test_declared_bot_with_browser_tokens(self):
        self.assertEqual("declared", classify_ua(GPTBOT))

    def test_tools(self):
        for ua in ("curl/8.5.0", "python-requests/2.32", "Go-http-client/2.0", "", "Mozilla/5.0 HeadlessChrome/155.0"):
            self.assertEqual("tool", classify_ua(ua), ua)

    def test_unrecognised_product_is_other(self):
        self.assertEqual("other", classify_ua("qoderclicn"))

    def test_agent_name_prefers_compatible_token(self):
        self.assertEqual("GPTBot", agent_name(GPTBOT))
        self.assertEqual("ChatGPT-User", agent_name("Mozilla/5.0 (KHTML, like Gecko); compatible; ChatGPT-User/1.0"))
        self.assertEqual("Applebot", agent_name("Mozilla/5.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com)"))


class FetcherDetectionTest(unittest.TestCase):
    def test_finds_muse_like_fetcher_without_known_networks(self):
        result = analyse(human_traffic() + muse_like_fetcher())

        self.assertEqual(1, len(result.fetchers))
        fetcher = result.fetchers[0]
        self.assertEqual(STALE_LINUX_CHROME, fetcher.ua)
        self.assertIn("never loads assets", fetcher.flags)
        self.assertTrue(any(f.startswith("rotating IPs") for f in fetcher.flags))
        self.assertTrue(any(f.startswith("browser 16 versions") for f in fetcher.flags))

    def test_real_visitors_are_not_flagged(self):
        result = analyse(human_traffic())
        self.assertEqual([], result.fetchers)

    def test_headless_alone_is_not_enough(self):
        # Returning visitors on current Chrome with cached assets: one IP, no second signal.
        rows = human_traffic() + [
            request("198.51.100.7", "/page/", at=START + timedelta(hours=h), referer="https://example.org/")
            for h in range(6)
        ]
        self.assertEqual([], analyse(rows).fetchers)

    def test_rotating_current_browser_is_a_lead_not_a_fetcher(self):
        proxy_ua = CURRENT_CHROME.replace("Windows NT 10.0", "Linux; Android 15")
        rows = human_traffic() + [
            request(f"100.64.{i}.1", f"/p{i}/", ua=proxy_ua, at=START + timedelta(minutes=i)) for i in range(10)
        ]
        result = analyse(rows)

        self.assertEqual([], result.fetchers)
        self.assertEqual([proxy_ua], [c.ua for c in result.rotators])

    def test_asset_baseline_is_reported(self):
        self.assertEqual(1.0, analyse(human_traffic()).asset_baseline)

    def test_small_clusters_are_ignored(self):
        rows = human_traffic() + muse_like_fetcher(days=2, extra_paths=())
        self.assertEqual([], analyse(rows, min_requests=5).fetchers)

    def test_known_cluster_labels_but_does_not_detect(self):
        muse = NamedRanges("muse", "Muse (probable)", (ipaddress.ip_network("87.81.224.0/19"),))
        result = analyse(human_traffic() + muse_like_fetcher(), known=[muse])
        self.assertEqual(9, result.fetchers[0].labels["Muse (probable)"])

        only_known = analyse(human_traffic(), known=[muse])
        self.assertEqual([], only_known.fetchers)

    def test_size_ratio_against_human_baseline(self):
        result = analyse(human_traffic() + muse_like_fetcher())
        self.assertAlmostEqual(34920 / 28000, result.fetchers[0].size_ratio, places=2)


class DeclaredAgentTest(unittest.TestCase):
    def test_declared_agents_are_counted_and_verified(self):
        openai = NamedRanges(
            "openai-gptbot", "OpenAI", (ipaddress.ip_network("20.171.0.0/16"),), tokens=("GPTBot",)
        )
        rows = [request("20.171.1.1", ua=GPTBOT), request("20.171.1.2", ua=GPTBOT), request("192.0.2.9", ua=GPTBOT)]
        result = analyse(rows, published=[openai])

        gptbot = next(d for d in result.declared if d.name == "GPTBot")
        self.assertEqual(3, gptbot.requests)
        self.assertAlmostEqual(2 / 3, gptbot.verified_share)

    def test_unverifiable_agents_report_none(self):
        result = analyse([request("192.0.2.9", ua="Mozilla/5.0 (compatible; Barkrowler/0.9)")])
        self.assertIsNone(result.declared[0].verified_share)

    def test_browser_ua_from_published_range_is_reported(self):
        openai = NamedRanges("openai-chatgpt-user", "OpenAI", (ipaddress.ip_network("20.171.0.0/16"),))
        result = analyse([request("20.171.9.9")], published=[openai])
        self.assertEqual(1, result.range_browser_hits[("OpenAI", CURRENT_CHROME)])


class ScheduleTest(unittest.TestCase):
    def test_finds_daily_window(self):
        rows = [
            request(f"87.81.230.{d}", "/tokyo/", ua=STALE_LINUX_CHROME, at=START + timedelta(days=d, hours=10, minutes=33 + d))
            for d in range(6)
        ]
        schedules = find_schedules(rows, window_minutes=30)

        self.assertEqual(1, len(schedules))
        self.assertEqual(10 * 60 + 33, schedules[0].window_start)
        self.assertEqual(6, len(schedules[0].days))

    def test_window_wraps_past_midnight(self):
        rows = [
            request("192.0.2.1", "/x/", at=START + timedelta(days=d, hours=23, minutes=50) + timedelta(minutes=15 * (d % 2)))
            for d in range(5)
        ]
        self.assertEqual(1, len(find_schedules(rows, window_minutes=30)))

    def test_scattered_times_are_not_a_schedule(self):
        rows = [request("192.0.2.1", "/x/", at=START + timedelta(days=d, hours=(d * 5) % 24)) for d in range(6)]
        self.assertEqual([], find_schedules(rows, window_minutes=30))


if __name__ == "__main__":
    unittest.main()
