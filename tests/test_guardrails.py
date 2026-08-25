import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class GuardrailTests(unittest.TestCase):
    """The crawler must stay GET-only and must not invoke scanners."""

    def _src(self, name: str) -> str:
        return (ROOT / "web_recon" / name).read_text(encoding="utf-8")

    def test_crawler_does_not_submit_or_scan(self):
        src = self._src("crawler.py")
        for needle in ("page.fill", "page.click", "page.type", "page.check", "subprocess", "os.system"):
            self.assertNotIn(needle, src)
        # Docstring may name scanners as things we do NOT run; assert we never import/call them.
        self.assertNotIn("import sqlmap", src)
        self.assertNotIn("shutil.which", src)

    def test_no_reflection_flag_set_by_crawler(self):
        combined = "".join(self._src(n) for n in ("crawler.py", "extract.py", "pipeline.py"))
        self.assertNotIn("reflects_in_template_context", combined)


if __name__ == "__main__":
    unittest.main()
