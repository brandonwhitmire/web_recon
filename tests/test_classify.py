import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.classify import classify_all, fill_placeholders, mapping_for
from web_recon.models import Fingerprint, FormField, FormRecord, PageRecord, ReconResult
from web_recon.report import render_classified
from web_recon.util import parse_robots, parse_sitemap_locs
from web_recon_heuristics import classify_input, classify_sqli_surface, sqli_pastables


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
        q = next(s for s in surfaces if s.param == "q")
        self.assertIn("sqli", q.classes)
        self.assertEqual(q.sqli_priority, "HIGH")
        self.assertNotIn("sqli", lfi.classes)
        md = render_classified(
            ReconResult(
                target="box.web",
                start_url="http://box.web/index.php",
                origin="http://box.web",
                slug="box.web",
                output_dir="/tmp",
                fingerprint=Fingerprint(),
                pages=[page],
                surfaces=surfaces,
            ),
            include_verbose=False,
        )
        self.assertLess(md.find("## sqli"), md.find("## file_inclusion"))
        self.assertLess(md.find("## file_inclusion"), md.find("## xss"))
        self.assertLess(md.find("## xss"), md.find("## verb_tampering"))
        self.assertNotIn("## Surfaces", md)

    def test_options_allow_annotates_site_surface(self):
        page = PageRecord(
            url="http://box.web/",
            final_url="http://box.web/",
            status=200,
        )
        surfaces = classify_all(
            [page],
            origin="http://box.web",
            attacker_ip="1.2.3.4",
            php_files=[],
            options_allow=["GET", "PUT", "DELETE", "OPTIONS"],
        )
        site = next(s for s in surfaces if s.kind == "site")
        self.assertIn("from_options_header", site.context_flags)
        self.assertEqual(site.sample_value, "GET, PUT, DELETE, OPTIONS")
        self.assertIn("OPTIONS Allow: GET, PUT, DELETE, OPTIONS", site.evidence)
        self.assertIn("verb_tampering", site.classes)


class SqliSurfaceTests(unittest.TestCase):
    def hit(self, **kwargs):
        return classify_sqli_surface(**kwargs)

    def test_login_username_and_password_high(self):
        user = self.hit(
            param_name="username",
            field_type="text",
            method="POST",
            kind="form_field",
            context_flags={"is_login_form", "is_username_field", "is_free_text"},
        )
        pwd = self.hit(
            param_name="password",
            field_type="password",
            method="POST",
            kind="form_field",
            context_flags={"is_login_form", "is_password_field"},
        )
        self.assertEqual(user["priority"], "HIGH")
        self.assertEqual(user["role"], "login")
        self.assertEqual(pwd["priority"], "HIGH")
        self.assertEqual(pwd["role"], "login")

    def test_login_csrf_and_remember_silent(self):
        self.assertIsNone(
            self.hit(
                param_name="csrf_token",
                field_type="hidden",
                method="POST",
                kind="form_field",
                context_flags={"is_login_form"},
            )
        )
        self.assertIsNone(
            self.hit(
                param_name="id",
                field_type="hidden",
                method="POST",
                kind="form_field",
                context_flags={"is_login_form"},
            )
        )
        self.assertIsNone(
            self.hit(
                param_name="remember",
                field_type="checkbox",
                method="POST",
                kind="form_field",
                context_flags={"is_login_form"},
            )
        )

    def test_search_q_s_item_high(self):
        q = self.hit(
            param_name="q",
            field_type="search",
            method="GET",
            kind="form_field",
            context_flags={"is_search_field", "is_free_text"},
        )
        self.assertEqual(q["priority"], "HIGH")
        self.assertEqual(q["role"], "search")
        s = self.hit(param_name="s", method="GET", kind="query_param")
        self.assertEqual(s["priority"], "HIGH")
        item = self.hit(param_name="item", method="GET", kind="query_param")
        self.assertEqual(item["priority"], "HIGH")
        self.assertEqual(item["role"], "search")

    def test_id_get_high_post_hidden_silent(self):
        got = self.hit(param_name="id", method="GET", kind="query_param")
        self.assertEqual(got["priority"], "HIGH")
        self.assertEqual(got["role"], "id")
        self.assertIsNone(
            self.hit(
                param_name="id",
                field_type="hidden",
                method="POST",
                kind="form_field",
            )
        )

    def test_page_is_not_sqli_page_id_is(self):
        self.assertIsNone(self.hit(param_name="page", method="GET", kind="query_param"))
        self.assertEqual(
            self.hit(param_name="page_id", method="GET", kind="query_param")["priority"],
            "HIGH",
        )

    def test_unrelated_freetext_and_upload_silent(self):
        self.assertIsNone(
            self.hit(
                param_name="title",
                field_type="text",
                method="POST",
                kind="form_field",
                context_flags={"is_free_text"},
            )
        )
        self.assertIsNone(
            self.hit(
                param_name="avatar",
                field_type="file",
                method="POST",
                kind="form_field",
                context_flags={"is_file_input"},
            )
        )
        self.assertIsNone(self.hit(param_name="id"))

    def test_filter_medium_cat_stays_high(self):
        filt = self.hit(param_name="sort", method="GET", kind="query_param")
        self.assertEqual(filt["priority"], "MEDIUM")
        self.assertEqual(filt["role"], "filter")
        cat = self.hit(param_name="cat", method="GET", kind="query_param")
        self.assertEqual(cat["priority"], "HIGH")
        self.assertEqual(cat["role"], "id")
        order = self.hit(param_name="order", method="GET", kind="query_param")
        self.assertEqual(order["priority"], "HIGH")

    def test_login_adjacent_newsletter_comment_medium(self):
        reset = self.hit(
            param_name="email",
            field_type="email",
            method="POST",
            kind="form_field",
            context_flags={"is_login_adjacent_form", "is_username_field"},
        )
        self.assertEqual(reset["priority"], "MEDIUM")
        self.assertEqual(reset["role"], "login_adjacent")
        news = self.hit(
            param_name="email",
            field_type="email",
            method="POST",
            kind="form_field",
            context_flags={"is_newsletter_form"},
        )
        self.assertEqual(news["priority"], "MEDIUM")
        comment = self.hit(
            param_name="comment",
            field_type="textarea",
            method="POST",
            kind="form_field",
            context_flags={"is_comment_form", "is_free_text"},
        )
        self.assertEqual(comment["priority"], "MEDIUM")

    def test_comment_form_name_is_not_search_high(self):
        self.assertIsNone(
            self.hit(
                param_name="name",
                field_type="text",
                method="POST",
                kind="form_field",
                context_flags={"is_comment_form", "is_free_text"},
            )
        )

    def test_pastables_login_auth_search_union_no_sqlmap(self):
        login = sqli_pastables("login", verbose=False)
        self.assertIn("admin' -- -", login["commands"])
        self.assertIn("' OR 1=1 IN (SELECT @@version) -- -", login["commands"])
        search = sqli_pastables("search", verbose=False)
        self.assertNotIn("' UNION SELECT 1,2,3,4,5 -- -", search["commands"])
        search_v = sqli_pastables("search", verbose=True, param="item")
        self.assertIn("' UNION SELECT 1,2,3,4,5 -- -", search_v["commands"])
        self.assertTrue(any("%'" in c for c in search_v["commands"]))
        for role in ("login", "search", "id", "filter", "comment"):
            blob = "\n".join(sqli_pastables(role, verbose=True)["commands"]).lower()
            self.assertNotIn("sqlmap", blob)
            self.assertIn("--path-as-is", blob)
            self.assertIn("--data-urlencode", blob)


class SqliPipelineTests(unittest.TestCase):
    def test_login_uid_title_and_report_section(self):
        page = PageRecord(
            url="http://box.web/login.php",
            final_url="http://box.web/login.php",
            status=200,
            query_params=[("uid", "1"), ("title", "hi")],
            forms=[
                FormRecord(
                    action="http://box.web/login.php",
                    method="POST",
                    enctype="application/x-www-form-urlencoded",
                    fields=[
                        FormField(
                            name="username",
                            field_type="text",
                            flags=["is_free_text", "is_login_form", "is_username_field"],
                        ),
                        FormField(
                            name="password",
                            field_type="password",
                            flags=["is_login_form", "is_password_field"],
                        ),
                        FormField(name="csrf", field_type="hidden", flags=["is_login_form"]),
                    ],
                )
            ],
        )
        surfaces = classify_all([page], origin="http://box.web", attacker_ip="1.2.3.4", php_files=[])
        by = {s.param: s for s in surfaces if s.kind != "site"}
        self.assertEqual(by["username"].sqli_priority, "HIGH")
        self.assertIn("sqli", by["username"].classes)
        self.assertIn("admin' -- -", by["username"].canonical["sqli"])
        self.assertIn("sqli", by["password"].classes)
        self.assertNotIn("sqli", by["csrf"].classes)
        self.assertEqual(by["uid"].sqli_priority, "HIGH")
        self.assertIn("sqli", by["uid"].classes)
        self.assertNotIn("sqli", by["title"].classes)

        result = ReconResult(
            target="box.web",
            start_url="http://box.web/login.php",
            origin="http://box.web",
            slug="box.web",
            output_dir="/tmp",
            fingerprint=Fingerprint(),
            pages=[page],
            surfaces=surfaces,
            class_counts={"sqli": 3},
        )
        md = render_classified(result, include_verbose=False)
        self.assertIn("## sqli", md)
        self.assertIn("### HIGH", md)
        self.assertIn("admin' -- -", md)
        self.assertNotIn("sqlmap -", md.lower())
        self.assertNotIn("' UNION SELECT 1,2,3,4,5 -- -", md)


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
