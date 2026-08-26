import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.models import Fingerprint, Header, RobotsInfo, SitemapInfo, TechHit
from web_recon.report import print_phase1


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


if __name__ == "__main__":
    unittest.main()
