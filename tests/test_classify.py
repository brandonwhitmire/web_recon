import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.classify import classify_all, fill_placeholders, mapping_for
from web_recon.models import FormField, FormRecord, PageRecord
from web_recon.util import parse_robots, parse_sitemap_locs
from web_recon_heuristics import classify_input


class HeuristicTests(unittest.TestCase):
    def test_page_param_is_lfi(self):
        self.assertIn("file_inclusion", classify_input("page", set()))

    def test_url_param_is_ssrf(self):
        self.assertIn("ssrf", classify_input("redirect_url", set()))

    def test_free_text_is_xss_and_ssti(self):
        classes = classify_input("q", {"is_free_text", "is_search_field"})
        self.assertIn("xss", classes)
        self.assertIn("ssti", classes)

    def test_file_input_is_upload(self):
        self.assertIn("file_upload", classify_input("avatar", {"is_file_input"}))


class PlaceholderTests(unittest.TestCase):
    def test_fills_known_and_keeps_unknown(self):
        text = "curl -sko- --path-as-is 'http://<TARGET>/<PAGE>?<PARAM>=../../../../etc/passwd' # <ATTACKER_IP> <FILE>"
        mapping = mapping_for(
            origin="http://10.10.11.12",
            page_url="http://10.10.11.12/index.php",
            param="page",
            attacker_ip=None,
            php_file="index.php",
        )
        out = fill_placeholders(text, mapping)
        self.assertIn("http://10.10.11.12/index.php?page=", out)
        self.assertIn("<ATTACKER_IP>", out)
        self.assertIn("index.php", out)

    def test_https_origin_rewrites_http_template(self):
        mapping = mapping_for(
            origin="https://box.web",
            page_url="https://box.web/search.php",
            param="q",
            attacker_ip="10.10.14.8",
            php_file=None,
        )
        out = fill_placeholders("curl 'http://<TARGET>/<PAGE>?<PARAM>=x' http://<ATTACKER_IP>/", mapping)
        self.assertIn("https://box.web/search.php?q=x", out)
        self.assertIn("http://10.10.14.8/", out)


class SurfacePipelineTests(unittest.TestCase):
    def test_classifies_form_and_query(self):
        page = PageRecord(
            url="http://box.web/index.php?page=home",
            final_url="http://box.web/index.php?page=home",
            status=200,
            query_params=[("page", "home")],
            forms=[
                FormRecord(
                    action="http://box.web/search.php",
                    method="GET",
                    enctype="application/x-www-form-urlencoded",
                    fields=[
                        FormField(name="q", field_type="search", flags=["is_free_text", "is_search_field"]),
                    ],
                )
            ],
        )
        surfaces = classify_all([page], origin="http://box.web", attacker_ip="1.2.3.4", php_files=["index.php"])
        classes = {s.param: s.classes for s in surfaces}
        self.assertIn("file_inclusion", classes.get("page", []))
        self.assertIn("xss", classes.get("q", []))
        self.assertTrue(any(s.kind == "site" and "verb_tampering" in s.classes for s in surfaces))
        lfi = next(s for s in surfaces if s.param == "page")
        blob = "\n".join(lfi.canonical["file_inclusion"])
        self.assertIn("index.php?page=", blob)
        self.assertNotIn("<PARAM>", blob)
        self.assertNotIn("xss", lfi.classes)


class RobotsSitemapTests(unittest.TestCase):
    def test_robots(self):
        raw = "User-agent: *\nDisallow: /admin\nAllow: /\nSitemap: http://box.web/sitemap.xml\n"
        info = parse_robots(raw, "http://box.web/robots.txt")
        self.assertEqual(info.disallow, ["/admin"])
        self.assertEqual(info.sitemaps, ["http://box.web/sitemap.xml"])

    def test_sitemap_urlset(self):
        xml = """<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>http://box.web/a</loc></url>
          <url><loc>http://box.web/b</loc></url>
        </urlset>"""
        urls, nested = parse_sitemap_locs(xml)
        self.assertEqual(nested, [])
        self.assertEqual(urls, ["http://box.web/a", "http://box.web/b"])

    def test_sitemap_index(self):
        xml = """<?xml version="1.0"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap><loc>http://box.web/sm1.xml</loc></sitemap>
        </sitemapindex>"""
        urls, nested = parse_sitemap_locs(xml)
        self.assertEqual(urls, [])
        self.assertEqual(nested, ["http://box.web/sm1.xml"])


if __name__ == "__main__":
    unittest.main()
