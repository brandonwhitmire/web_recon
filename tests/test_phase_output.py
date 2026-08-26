import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.models import Fingerprint, Header, PageRecord, ReconResult, RobotsInfo, SitemapInfo, Surface, TechHit
from web_recon.report import iter_class_groups, print_overview, print_phase1, print_phase3


class Phase1PrintTests(unittest.TestCase):
    def test_order_is_headers_robots_wappalyzer_sitemap(self):
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
                )
        self.assertIn("Phase 1", infos[0])
        self.assertEqual(infos[1:], ["HTTP headers", "robots.txt", "Wappalyzer", "sitemap.xml"])
        blob = "\n".join(details)
        self.assertIn("Server: nginx", blob)
        self.assertIn("Disallow: /admin", blob)
        self.assertIn("WordPress", blob)
        self.assertIn("http://box.web/?p=1", blob)


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


if __name__ == "__main__":
    unittest.main()
