import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.fingerprint import fingerprint_page
from web_recon.models import Header


class FingerprintTests(unittest.TestCase):
    def test_header_and_html_signatures(self):
        html = """
        <html><head>
          <meta name="generator" content="WordPress 6.4">
          <script src="/wp-includes/js/jquery/jquery.min.js"></script>
        </head>
        <body class="wp-content">hello</body></html>
        """
        fp = fingerprint_page(
            "http://box.web/",
            html,
            [Header(name="Server", value="Apache/2.4.41 (Ubuntu)"), Header(name="X-Powered-By", value="PHP/7.4.3")],
            cookies=[{"name": "PHPSESSID", "value": "abc"}],
        )
        names = " ".join(h.name for h in fp.hits)
        self.assertIn("Ubuntu", fp.os_hints)
        self.assertIn("PHP", names)
        self.assertTrue(any("WordPress" in h.name or "WordPress" in (h.evidence or "") for h in fp.hits) or "WordPress" in names)

    def test_wappalyzer_library_is_required_dep(self):
        from web_recon.fingerprint import _HAS_WAPPALYZER, _wappalyzer

        self.assertTrue(_HAS_WAPPALYZER, "wappalyzer-python3 must be in requirements.txt / project dependencies")
        self.assertIsNotNone(_wappalyzer())
        html = '<html><head><meta name="generator" content="WordPress 6.4"></head><body class="wp-content">x</body></html>'
        fp = fingerprint_page(
            "http://box.web/",
            html,
            [Header(name="Server", value="Apache/2.4.52 (Ubuntu)")],
        )
        self.assertTrue(fp.wappalyzer_available)
        self.assertTrue(any(h.source == "wappalyzer" for h in fp.hits))


if __name__ == "__main__":
    unittest.main()
