import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.discovery import discovery_sections, is_wordpress
from web_recon.models import Fingerprint, FormRecord, PageRecord, ReconResult, TechHit


def _result(**kwargs) -> ReconResult:
    base = dict(
        target="192.168.240.121",
        start_url="http://192.168.240.121/",
        origin="http://192.168.240.121",
        slug="192.168.240.121",
        output_dir="/tmp",
        fingerprint=Fingerprint(),
    )
    base.update(kwargs)
    return ReconResult(**base)


class DiscoveryPastableTests(unittest.TestCase):
    def test_ip_target_fills_url_and_leaves_unknown_domain(self):
        sections = dict(discovery_sections(_result(), resolve=False))
        self.assertEqual(list(sections), ["vHost Brute-Force", "Crawling", "Directory Brute-Forcing"])
        vhost = sections["vHost Brute-Force"]
        self.assertIn("-u http://192.168.240.121/", vhost)
        self.assertIn("Host: FUZZ.<DOMAIN>", vhost)
        self.assertIn("echo '192.168.240.121 <VHOST>.<FQDN>'", vhost)
        self.assertIn("-fs <SIZE>", vhost)
        crawl = sections["Crawling"]
        self.assertIn("katana -output katana_crawl.txt -depth 5 -u http://192.168.240.121", crawl)
        dirs = sections["Directory Brute-Forcing"]
        self.assertIn("-u http://192.168.240.121", dirs)
        self.assertIn("-x php,html,htm,txt,bak,zip,xml,json,js,sh,py,config", dirs)
        self.assertIn("linux/PHP", dirs)
        self.assertNotIn("WordPress", sections)

    def test_https_hostname_and_windows_extensions(self):
        result = _result(
            target="app.lab",
            start_url="https://app.lab/login.aspx",
            origin="https://app.lab",
            fingerprint=Fingerprint(server="Microsoft-IIS/10.0", os_hints=["Windows"]),
            pages=[
                PageRecord(
                    url="https://app.lab/login.aspx",
                    final_url="https://app.lab/login.aspx",
                    status=200,
                    forms=[FormRecord(action="/login.aspx", method="POST", enctype="")],
                )
            ],
        )
        sections = dict(discovery_sections(result, resolved_ip="10.10.11.12", resolve=False))
        vhost = sections["vHost Brute-Force"]
        self.assertIn("-u https://app.lab/", vhost)
        self.assertIn("Host: FUZZ.app.lab", vhost)
        self.assertIn("echo '10.10.11.12 <VHOST>.app.lab'", vhost)
        dirs = sections["Directory Brute-Forcing"]
        self.assertIn("-u https://app.lab", dirs)
        self.assertIn("-x asp,aspx,ashx,asmx,html,htm,txt,bak,zip,xml,json,js,config,cs", dirs)
        self.assertIn("windows/IIS/ASP.NET", dirs)
        self.assertIn("https://app.lab", sections["Crawling"])

    def test_wordpress_pastable_includes_api_links(self):
        result = _result(
            fingerprint=Fingerprint(
                hits=[TechHit(name="WordPress", category="CMS", version="6.4", source="html")]
            ),
            pages=[
                PageRecord(
                    url="http://192.168.240.121/",
                    final_url="http://192.168.240.121/",
                    status=200,
                    links=["http://192.168.240.121/wp-login.php", "http://192.168.240.121/wp-content/plugins/x"],
                )
            ],
        )
        self.assertTrue(is_wordpress(result))
        sections = dict(discovery_sections(result, resolve=False))
        wp = sections["WordPress"]
        self.assertIn("https://wpscan.com/api/", wp)
        self.assertIn("https://wpscan.com/profile/", wp)
        self.assertIn("fingerprint: WordPress 6.4 [html]", wp)
        self.assertIn("/wp-login.php", wp)
        self.assertIn("--url http://192.168.240.121", wp)
        self.assertIn("--api-token <API_TOKEN>", wp)
        self.assertIn("curl -s http://192.168.240.121/wp-json/wp/v2/users", wp)


if __name__ == "__main__":
    unittest.main()
