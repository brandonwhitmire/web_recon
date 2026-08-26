import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.cache import crawl_key, keys_match, normalize_start_url, result_from_inventory, try_cache
from web_recon.cli import build_parser
from web_recon.filters import CLASS_KEYS, classes_from_args, flag_to_class
from web_recon.models import Config, Header, OptionsInfo, ReconResult, Surface
from web_recon.report import render_inventory


class FilterFlagTests(unittest.TestCase):
    def test_every_classifier_has_a_flag(self):
        mapped = {key for _cli, key in __import__("web_recon.filters", fromlist=["FILTER_FLAGS"]).FILTER_FLAGS}
        self.assertTrue(set(CLASS_KEYS) <= mapped, set(CLASS_KEYS) - mapped)

    def test_flag_order_does_not_matter(self):
        p = build_parser()
        a = classes_from_args(p.parse_args(["http://box.web", "--xss", "--sqli"]))
        b = classes_from_args(p.parse_args(["http://box.web", "--sqli", "--xss"]))
        self.assertEqual(set(a), set(b))
        self.assertEqual(set(a), {"xss", "sqli"})

    def test_aliases(self):
        self.assertEqual(flag_to_class("lfi"), "file_inclusion")
        self.assertEqual(flag_to_class("cmdi"), "command_injection")
        p = build_parser()
        args = p.parse_args(["http://box.web", "--lfi", "--file-inclusion"])
        self.assertEqual(classes_from_args(args), ["file_inclusion"])

    def test_debug_flag(self):
        p = build_parser()
        args = p.parse_args(["http://box.web", "--debug"])
        self.assertTrue(args.debug)
        self.assertFalse(p.parse_args(["http://box.web"]).debug)


class CacheKeyTests(unittest.TestCase):
    def test_url_normalization(self):
        self.assertEqual(normalize_start_url("box.web"), "http://box.web")
        self.assertEqual(normalize_start_url("http://box.web/"), "http://box.web")
        self.assertEqual(normalize_start_url("http://Box.web/app/"), "http://box.web/app")

    def test_same_options_different_construction_match(self):
        a = crawl_key(Config(start_url="http://box.web", max_pages=80, verbose=True))
        b = crawl_key(Config(start_url="http://box.web/", max_pages=80, verbose=False, class_filters=["sqli"]))
        self.assertTrue(keys_match(a, b))

    def test_max_pages_mismatch(self):
        a = crawl_key(Config(start_url="http://box.web", max_pages=40))
        b = crawl_key(Config(start_url="http://box.web", max_pages=80))
        self.assertFalse(keys_match(a, b))

    def test_debug_and_verbose_do_not_change_key(self):
        a = crawl_key(Config(start_url="http://box.web", debug=True, verbose=True))
        b = crawl_key(Config(start_url="http://box.web", debug=False, verbose=False))
        self.assertTrue(keys_match(a, b))


class CacheRoundtripTests(unittest.TestCase):
    def test_try_cache_hit_and_miss(self):
        tmp = Path(tempfile.mkdtemp(prefix="web-recon-cache-"))
        cfg = Config(start_url="http://box.web", max_pages=80)
        result = ReconResult(
            target="box.web",
            start_url="http://box.web",
            origin="http://box.web",
            slug="box.web",
            output_dir=str(tmp),
            config={"crawl": crawl_key(cfg)},
            options=OptionsInfo(
                url="http://box.web/",
                fetched=True,
                status=200,
                allow=["GET", "HEAD", "OPTIONS"],
                headers=[Header(name="Allow", value="GET, HEAD, OPTIONS")],
            ),
            surfaces=[
                Surface(
                    id="s1",
                    kind="query_param",
                    page_url="http://box.web/view.html",
                    page_path="view.html",
                    method="GET",
                    param="page",
                    classes=["file_inclusion"],
                    canonical={"file_inclusion": ["../../../../etc/passwd"]},
                )
            ],
            class_counts={"file_inclusion": 1},
        )
        (tmp / "inventory.json").write_text(render_inventory(result), encoding="utf-8")

        hit = try_cache(tmp, crawl_key(cfg))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.surfaces[0].param, "page")
        self.assertIn("file_inclusion", hit.surfaces[0].classes)
        self.assertIsNotNone(hit.options)
        self.assertEqual(hit.options.allow, ["GET", "HEAD", "OPTIONS"])
        self.assertEqual(hit.options.headers[0].name, "Allow")

        miss = try_cache(tmp, crawl_key(Config(start_url="http://box.web", max_pages=10)))
        self.assertIsNone(miss)

        loaded = result_from_inventory(json.loads((tmp / "inventory.json").read_text()), str(tmp))
        self.assertEqual(loaded.config["crawl"]["max_pages"], 80)
        self.assertEqual(loaded.options.allow, ["GET", "HEAD", "OPTIONS"])

    def test_old_inventory_without_options_is_none(self):
        loaded = result_from_inventory(
            {
                "target": "box.web",
                "start_url": "http://box.web",
                "origin": "http://box.web",
                "slug": "box.web",
                "surfaces": [],
            },
            "/tmp",
        )
        self.assertIsNone(loaded.options)


class HelpTests(unittest.TestCase):
    def test_help_lists_filters_and_force(self):
        text = build_parser().format_help()
        for flag in ("--sqli", "--xss", "--lfi", "--force-rescan", "--cmdi", "--verb-tampering", "--debug"):
            self.assertIn(flag, text)


if __name__ == "__main__":
    unittest.main()
