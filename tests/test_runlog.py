import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.runlog import RunLog


class RunLogTests(unittest.TestCase):
    def test_errors_log_always_written(self):
        tmp = Path(tempfile.mkdtemp(prefix="web-recon-log-"))
        log = RunLog(tmp, debug=False, target="http://box.web")
        log.error("timeout after 20000ms")
        log.close()
        err = (tmp / "errors.log").read_text(encoding="utf-8")
        self.assertIn("timeout after 20000ms", err)
        self.assertFalse((tmp / "debug.log").exists())

    def test_debug_log_only_when_enabled(self):
        tmp = Path(tempfile.mkdtemp(prefix="web-recon-log-"))
        log = RunLog(tmp, debug=True, target="http://box.web")
        log.debug("visit depth=0 http://box.web/")
        log.error("page failed")
        log.close()
        dbg = (tmp / "debug.log").read_text(encoding="utf-8")
        self.assertIn("visit depth=0", dbg)
        self.assertIn("ERROR page failed", dbg)
        err = (tmp / "errors.log").read_text(encoding="utf-8")
        self.assertIn("page failed", err)

    def test_no_errors_placeholder(self):
        tmp = Path(tempfile.mkdtemp(prefix="web-recon-log-"))
        log = RunLog(tmp, debug=False, target="http://box.web")
        log.close()
        text = (tmp / "errors.log").read_text(encoding="utf-8")
        self.assertIn("No errors captured.", text)

    def test_exception_traceback_in_errors(self):
        tmp = Path(tempfile.mkdtemp(prefix="web-recon-log-"))
        log = RunLog(tmp, debug=True, target="http://box.web")
        try:
            raise ValueError("boom")
        except ValueError as exc:
            log.error("fatal: boom", exc=exc)
        log.close()
        err = (tmp / "errors.log").read_text(encoding="utf-8")
        self.assertIn("ValueError: boom", err)
        self.assertIn("Traceback", err)


if __name__ == "__main__":
    unittest.main()
