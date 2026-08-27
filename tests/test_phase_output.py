import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.models import Fingerprint, Header, OptionsInfo, PageRecord, ReconResult, RobotsInfo, SitemapInfo, Surface, TechHit
from web_recon.report import iter_class_groups, print_overview, print_phase1, print_phase3


class Phase1PrintTests(unittest.TestCase):
    def test_order_is_headers_options_robots_wappalyzer_sitemap(self):
        infos: list[str] = []
        details: list[str] = []
        with patch("web_recon.report.info", side_effect=lambda m: infos.append(m)):
            with patch("web_recon.report.detail", side_effect=lambda m: details.append(m)):
                print_phase1(
                    "http://box.web/",
                    [Header(name="Server", value="nginx")],
                    RobotsInfo(
                        url="http://box.web/robots.txt",
                        fetched=True,
                        status=200,
                        disallow=["/admin"],
                        raw="User-agent: *\nDisallow: /admin\n",
                    ),
                    Fingerprint(
                        wappalyzer_available=True,
                        hits=[TechHit(name="WordPress", category="CMS", source="html")],
                    ),
                    SitemapInfo(
                        requested=["http://box.web/sitemap.xml"],
                        urls=["http://box.web/", "http://box.web/?p=1"],
                    ),
                    options=OptionsInfo(
                        url="http://box.web/",
                        fetched=True,
                        status=200,
                        allow=["GET", "HEAD", "POST", "OPTIONS"],
                        headers=[
                            Header(name="Allow", value="GET, HEAD, POST, OPTIONS"),
                            Header(name="Access-Control-Allow-Origin", value="*"),
                        ],
                    ),
                )
        self.assertIn("Phase 1", infos[0])
        self.assertEqual(
            infos[1:],
            ["HTTP headers", "HTTP OPTIONS", "robots.txt", "Wappalyzer", "sitemap.xml"],
        )
        blob = "\n".join(details)
        self.assertIn("Server: nginx", blob)
        self.assertIn("GET, HEAD, POST, OPTIONS", blob)
        self.assertNotIn("Access-Control-Allow-Origin", blob)
        self.assertNotIn("Allow: GET", blob)
        self.assertIn("Disallow: /admin", blob)
        self.assertIn("WordPress", blob)
        self.assertIn("http://box.web/?p=1", blob)

    def test_options_prints_verbs_only(self):
        details: list[str] = []
        with patch("web_recon.report.info"):
            with patch("web_recon.report.detail", side_effect=lambda m: details.append(m)):
                print_phase1(
                    "http://box.web/",
                    [],
                    None,
                    Fingerprint(wappalyzer_available=True),
                    None,
                    options=OptionsInfo(
                        url="http://box.web/",
                        fetched=True,
                        status=200,
                        allow=["GET", "PUT", "DELETE", "OPTIONS"],
                        headers=[
                            Header(name="Allow", value="GET, PUT, DELETE, OPTIONS"),
                            Header(name="Access-Control-Allow-Origin", value="*"),
                            Header(name="Server", value="nginx"),
                        ],
                    ),
                    include_banner=False,
                )
        blob = "\n".join(details)
        self.assertIn("GET, PUT, DELETE, OPTIONS", blob)
        self.assertNotIn("status=200", blob)
        self.assertNotIn("interesting methods", blob)
        self.assertNotIn("Access-Control-Allow-Origin", blob)
        self.assertNotIn("Server: nginx", blob)
        self.assertNotIn("Allow:", blob)

    def test_options_405_still_prints_advertised_verbs(self):
        details: list[str] = []
        with patch("web_recon.report.info"):
            with patch("web_recon.report.detail", side_effect=lambda m: details.append(m)):
                print_phase1(
                    "http://box.web/",
                    [],
                    None,
                    Fingerprint(wappalyzer_available=True),
                    None,
                    options=OptionsInfo(
                        url="http://box.web/",
                        fetched=True,
                        status=405,
                        allow=["GET", "HEAD", "OPTIONS"],
                        headers=[Header(name="Allow", value="GET, HEAD, OPTIONS")],
                    ),
                    include_banner=False,
                )
        blob = "\n".join(details)
        self.assertIn("GET, HEAD, OPTIONS", blob)
        self.assertNotIn("status=405", blob)
        self.assertNotIn("HTTP 405", blob)

    def test_options_without_allow_says_none_advertised(self):
        details: list[str] = []
        with patch("web_recon.report.info"):
            with patch("web_recon.report.detail", side_effect=lambda m: details.append(m)):
                print_phase1(
                    "http://box.web/",
                    [Header(name="Server", value="Apache")],
                    RobotsInfo(
                        url="http://box.web/robots.txt",
                        fetched=True,
                        status=404,
                        raw="<!DOCTYPE HTML><html>404</html>",
                        error="HTTP 404",
                    ),
                    Fingerprint(wappalyzer_available=True, hits=[TechHit(name="Apache", category="Web servers", source="wappalyzer")]),
                    SitemapInfo(
                        requested=["http://box.web/sitemap.xml"],
                        urls=[],
                        errors=["http://box.web/sitemap.xml: HTTP 404"],
                    ),
                    options=OptionsInfo(
                        url="http://box.web/",
                        fetched=True,
                        status=404,
                        error="HTTP 404",
                        headers=[Header(name="Content-Type", value="text/html")],
                    ),
                    include_banner=False,
                )
        blob = "\n".join(details)
        self.assertIn("(none advertised)", blob)
        self.assertTrue(any(d.strip() == "(none advertised)" for d in details))
        self.assertNotIn("DOCTYPE", blob)
        self.assertNotIn("interesting methods", blob)

    def test_robots_and_sitemap_404_are_one_line(self):
        details: list[str] = []
        with patch("web_recon.report.info"):
            with patch("web_recon.report.detail", side_effect=lambda m: details.append(m)):
                print_phase1(
                    "http://box.web/",
                    [Header(name="Server", value="Apache")],
                    RobotsInfo(
                        url="http://box.web/robots.txt",
                        fetched=True,
                        status=404,
                        raw="<!DOCTYPE HTML><html>404</html>",
                        error="HTTP 404",
                    ),
                    Fingerprint(wappalyzer_available=True, hits=[TechHit(name="Apache", category="Web servers", source="wappalyzer")]),
                    SitemapInfo(
                        requested=["http://box.web/sitemap.xml"],
                        urls=[],
                        errors=["http://box.web/sitemap.xml: HTTP 404"],
                    ),
                    include_banner=False,
                )
        blob = "\n".join(details)
        self.assertIn("HTTP 404  http://box.web/robots.txt", blob)
        self.assertIn("HTTP 404  http://box.web/sitemap.xml", blob)
        self.assertNotIn("Disallow", blob)
        self.assertNotIn("DOCTYPE", blob)
        self.assertNotIn("entries: 0", blob)
        self.assertNotIn("(none)", blob)
        self.assertNotIn("not installed", blob)
        self.assertIn("Apache", blob)

    def test_wappalyzer_missing_shows_install_hint(self):
        details: list[str] = []
        with patch("web_recon.report.info"):
            with patch("web_recon.report.detail", side_effect=lambda m: details.append(m)):
                print_phase1(
                    "http://box.web/",
                    [Header(name="Server", value="Apache")],
                    None,
                    Fingerprint(wappalyzer_available=False, hits=[TechHit(name="HTTP Server", category="Web server", source="header")]),
                    None,
                    include_banner=False,
                )
        blob = "\n".join(details)
        self.assertTrue(any("not installed" in d or "failed to load" in d for d in details), blob)
        self.assertIn("HTTP Server", blob)


class SummaryErrorTests(unittest.TestCase):
    def test_summary_omits_404_html(self):
        from web_recon.report import render_summary

        md = render_summary(
            ReconResult(
                target="box.web",
                start_url="http://box.web/",
                origin="http://box.web",
                slug="box.web",
                output_dir="/tmp",
                fingerprint=Fingerprint(),
                robots=RobotsInfo(
                    url="http://box.web/robots.txt",
                    fetched=True,
                    status=404,
                    raw="<!DOCTYPE HTML><html><title>404 Not Found</title></html>",
                    error="HTTP 404",
                ),
                sitemap=SitemapInfo(
                    requested=["http://box.web/sitemap.xml"],
                    errors=["http://box.web/sitemap.xml: HTTP 404"],
                ),
                options=OptionsInfo(
                    url="http://box.web/",
                    fetched=True,
                    status=404,
                    error="HTTP 404",
                    headers=[Header(name="Content-Type", value="text/html")],
                ),
            )
        )
        self.assertIn("HTTP 404  http://box.web/robots.txt", md)
        self.assertIn("HTTP 404  http://box.web/sitemap.xml", md)
        self.assertIn("HTTP OPTIONS (start URL)", md)
        self.assertIn("_None advertised._", md)
        self.assertNotIn("DOCTYPE", md)
        self.assertNotIn("Disallow", md)
        self.assertNotIn("### Raw", md)


def _surf(**kwargs) -> Surface:
    base = dict(
        id="s",
        kind="form_field",
        page_url="http://box.web/login.php",
        page_path="login.php",
        method="POST",
        param="x",
        classes=[],
        why={},
        canonical={},
    )
    base.update(kwargs)
    return Surface(**base)


class Phase3ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.result = ReconResult(
            target="box.web",
            start_url="http://box.web/",
            origin="http://box.web",
            slug="box.web",
            output_dir="/tmp",
            fingerprint=Fingerprint(),
            pages=[PageRecord(url="http://box.web/", final_url="http://box.web/", status=200)],
            surfaces=[
                _surf(
                    id="med",
                    param="email",
                    kind="form_field",
                    classes=["sqli", "xss"],
                    sqli_priority="MEDIUM",
                    sqli_role="newsletter",
                    why={"sqli": "newsletter", "xss": "free text"},
                    canonical={"sqli": ["med-payload"], "xss": ["xss-payload"]},
                ),
                _surf(
                    id="high",
                    param="username",
                    kind="form_field",
                    classes=["sqli"],
                    sqli_priority="HIGH",
                    sqli_role="login",
                    why={"sqli": "login"},
                    canonical={"sqli": ["high-payload"]},
                ),
                _surf(
                    id="lfi",
                    param="page",
                    kind="query_param",
                    method="GET",
                    page_path="index.php",
                    classes=["file_inclusion"],
                    why={"file_inclusion": "page param"},
                    canonical={"file_inclusion": ["../../../../etc/passwd"]},
                ),
                _surf(
                    id="vt",
                    param="*",
                    kind="site",
                    method="OPTIONS",
                    page_path="",
                    classes=["verb_tampering"],
                    canonical={"verb_tampering": ["curl -X PUT"]},
                ),
            ],
        )

    def test_groups_are_class_then_high_to_low(self):
        groups = iter_class_groups(self.result)
        names = [cls for cls, _ in groups]
        self.assertEqual(names, ["sqli", "file_inclusion", "xss", "verb_tampering"])
        sqli = dict(groups)["sqli"]
        self.assertEqual([s.param for s in sqli], ["username", "email"])
        self.assertEqual(sqli[0].sqli_priority, "HIGH")
        self.assertEqual(sqli[1].sqli_priority, "MEDIUM")

    def test_phase3_before_overview(self):
        infos: list[str] = []
        with patch("web_recon.report.info", side_effect=lambda m: infos.append(m)):
            with patch("builtins.print"):
                print_phase3(self.result, verbose=False)
                print_overview(self.result)
        i3 = next(i for i, m in enumerate(infos) if "Phase 3" in m)
        iov = next(i for i, m in enumerate(infos) if "Web Recon Overview" in m)
        self.assertLess(i3, iov)
        sqli_hdr = next(i for i, m in enumerate(infos) if m.startswith("{bmagenta}sqli"))
        xss_hdr = next(i for i, m in enumerate(infos) if m.startswith("{bmagenta}xss"))
        high = next(i for i, m in enumerate(infos) if "{byellow}HIGH{rst}" in m)
        med = next(i for i, m in enumerate(infos) if "{byellow}MEDIUM{rst}" in m)
        self.assertLess(sqli_hdr, high)
        self.assertLess(high, med)
        self.assertLess(med, xss_hdr)
        self.assertLess(xss_hdr, iov)

    def test_unnamed_text_omitted_from_terminal_kept_in_classified(self):
        from web_recon.report import render_classified

        self.result.surfaces.extend(
            [
                _surf(
                    id="unnamed-text",
                    param="(unnamed_text)",
                    kind="form_field",
                    method="GET",
                    page_path="",
                    classes=["xss"],
                    why={"xss": "free-text/search input"},
                    canonical={"xss": ["<script>alert(window.origin)</script>"]},
                ),
                _surf(
                    id="unnamed-ta",
                    param="(unnamed_textarea)",
                    kind="form_field",
                    method="GET",
                    page_path="contact_us.html",
                    classes=["xss"],
                    why={"xss": "free-text/search input"},
                    canonical={"xss": ["<svg/onload=alert(window.origin)>"]},
                ),
                _surf(
                    id="named",
                    param="name",
                    kind="form_field",
                    method="GET",
                    page_path="contact_us.html",
                    classes=["xss"],
                    why={"xss": "free-text/search input"},
                    canonical={"xss": ["<script>alert(window.origin)</script>"]},
                ),
            ]
        )
        infos: list[str] = []
        printed: list[str] = []
        with patch("web_recon.report.info", side_effect=lambda m: infos.append(m)):
            with patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(str(x) for x in a))):
                print_phase3(self.result, verbose=False)
                print_overview(self.result)
        blob = "\n".join(infos + printed)
        self.assertNotIn("(unnamed_text)", blob)
        self.assertNotIn("(unnamed_textarea)", blob)
        self.assertIn("param={bgreen}name{rst}", blob)
        self.assertTrue(any("unnamed text/textarea" in m and "classified.md" in m for m in infos))
        xss_hdr = next(m for m in infos if m.startswith("{bmagenta}xss"))
        self.assertEqual(xss_hdr, "{bmagenta}xss{rst}: {byellow}2{rst}")
        self.assertTrue(any("2{rst} unnamed text/textarea" in m for m in infos))
        md = render_classified(self.result, include_verbose=False)
        self.assertIn("`(unnamed_text)`", md)
        self.assertIn("`(unnamed_textarea)`", md)
        self.assertIn("`name`", md)


if __name__ == "__main__":
    unittest.main()
