import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.scope import (
    crawl_identity,
    in_scope,
    is_cdn_or_third_party,
    is_crawlable_page,
    is_static_asset,
    normalize_url,
    origin_of,
    page_path_of,
    target_slug,
)


class ScopeTests(unittest.TestCase):
    def test_exact_host_only(self):
        self.assertTrue(in_scope("http://box.web/login.php", "box.web"))
        self.assertFalse(in_scope("http://www.box.web/login.php", "box.web"))
        self.assertFalse(in_scope("http://other.web/", "box.web"))

    def test_cdn_excluded(self):
        self.assertTrue(is_cdn_or_third_party("cdnjs.cloudflare.com"))
        self.assertFalse(in_scope("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js", "box.web"))

    def test_multi_host_alias(self):
        hosts = {"10.10.11.12", "blog.web"}
        self.assertTrue(in_scope("http://blog.web/a", hosts))
        self.assertTrue(in_scope("http://10.10.11.12/a", hosts))
        self.assertFalse(in_scope("http://dev.blog.web/a", hosts))

    def test_tracking_params_stripped(self):
        a = normalize_url("http://box.web/x.php?id=1&utm_source=x")
        b = normalize_url("http://box.web/x.php?id=1")
        self.assertEqual(a, b)
        self.assertEqual(crawl_identity(a), crawl_identity(b))

    def test_fragment_dropped_unless_spa(self):
        self.assertEqual(normalize_url("http://box.web/a#section"), "http://box.web/a")
        self.assertTrue(normalize_url("http://box.web/a#/dashboard").endswith("#/dashboard"))

    def test_static_not_crawlable(self):
        self.assertTrue(is_static_asset("http://box.web/theme.css"))
        self.assertFalse(is_crawlable_page("http://box.web/logo.png"))
        self.assertTrue(is_crawlable_page("http://box.web/index.php"))

    def test_slug_and_path(self):
        self.assertEqual(target_slug("http://10.10.11.12:8080/app"), "10.10.11.12_8080")
        self.assertEqual(page_path_of("http://box.web/dir/view.php?id=1"), "dir/view.php")
        self.assertEqual(origin_of("http://box.web:80/x"), "http://box.web")


if __name__ == "__main__":
    unittest.main()
