import asyncio
import http.server
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from shutil import copytree

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE = ROOT / "tests" / "fixtures" / "site"


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


class E2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _chromium_available():
            raise unittest.SkipTest("Chromium not installed (playwright install chromium)")
        cls.site_dir = Path(tempfile.mkdtemp(prefix="web-recon-site-"))
        copytree(FIXTURE, cls.site_dir, dirs_exist_ok=True)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(cls.site_dir), **kwargs)

            def log_message(self, fmt, *args):
                return

        cls.httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.port}"
        for name in ("robots.txt", "sitemap.xml"):
            path = cls.site_dir / name
            path.write_text(path.read_text(encoding="utf-8").replace("REPLACE_ORIGIN", cls.origin), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_passive_crawl_classifies_surfaces(self):
        from web_recon.models import Config
        from web_recon.pipeline import run

        tmp = Path(tempfile.mkdtemp(prefix="web-recon-e2e-"))
        cfg = Config(
            start_url=self.origin + "/index.html",
            output_root=str(tmp),
            verbose=False,
            max_pages=20,
            max_depth=3,
            timeout_ms=15000,
            settle_ms=200,
            delay_s=0.0,
            enqueue_sitemap=True,
            attacker_ip="10.10.14.8",
        )
        result = asyncio.run(run(cfg))
        out = Path(result.output_dir)
        for name in ("summary.md", "crawl_map.md", "classified.md", "manual_checks.md", "inventory.json"):
            self.assertTrue((out / name).is_file(), name)
        params = {s.param: s.classes for s in result.surfaces}
        self.assertIn("file_inclusion", params.get("page", []), params)
        self.assertIn("xss", params.get("q", []), params)
        self.assertTrue(any("file_upload" in s.classes for s in result.surfaces if s.param == "avatar"))
        self.assertEqual(result.attacker_ip, "10.10.14.8")
        classified = (out / "classified.md").read_text(encoding="utf-8")
        self.assertIn("Candidate classes only", classified)
        self.assertIn("confirmed vulnerability", classified.lower())
        self.assertIn("## SQLi Candidate Surfaces", classified)
        manual = (out / "manual_checks.md").read_text(encoding="utf-8")
        self.assertIn("10.10.14.8", manual)
        summary = (out / "summary.md").read_text(encoding="utf-8")
        self.assertIn("/admin", summary)
        page_surface = next(s for s in result.surfaces if s.param == "page")
        self.assertIn("file_inclusion", page_surface.classes)
        self.assertNotIn("xss", page_surface.classes)


if __name__ == "__main__":
    unittest.main()
