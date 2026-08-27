"""Per-run log files under results/<target>/web_scan/.

errors.log  — always written (page/robots/sitemap/pipeline failures)
debug.log   — only with --debug (visit traces, hook noise, stack traces)
"""

from __future__ import annotations

import traceback
from datetime import datetime, timezone
from pathlib import Path


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def _format_exc(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


class RunLog:
    def __init__(self, out_dir: str | Path, *, debug: bool, target: str = "") -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.debug_enabled = bool(debug)
        self.target = target
        self.errors_path = self.out_dir / "errors.log"
        self.debug_path = self.out_dir / "debug.log"
        self._error_lines: list[str] = []
        self._debug_fh = None
        if self.debug_enabled:
            self._debug_fh = self.debug_path.open("w", encoding="utf-8")
            self._debug_fh.write(f"# web_recon debug.log\n# target: {target}\n# started: {_ts()}\n\n")
            self._debug_fh.flush()

    def error(self, msg: str, *, exc: BaseException | None = None) -> None:
        line = f"{_ts()}  {msg}"
        self._error_lines.append(line)
        if exc is not None:
            self._error_lines.append(_format_exc(exc).rstrip())
        self.debug("ERROR " + msg, exc=exc)

    def debug(self, msg: str, *, exc: BaseException | None = None) -> None:
        if self._debug_fh is None:
            return
        self._debug_fh.write(f"{_ts()}  {msg}\n")
        if exc is not None:
            self._debug_fh.write(_format_exc(exc))
        self._debug_fh.flush()

    @property
    def has_errors(self) -> bool:
        return bool(self._error_lines)

    def write_errors(self) -> Path:
        body = [
            "# web_recon errors.log",
            f"# target: {self.target}",
            f"# generated: {_ts()}",
            "",
        ]
        if self._error_lines:
            body.extend(self._error_lines)
            body.append("")
        else:
            body.append("No errors captured.")
            body.append("")
        self.errors_path.write_text("\n".join(body) + "\n", encoding="utf-8")
        return self.errors_path

    def close(self) -> None:
        self.write_errors()
        if self._debug_fh is not None:
            self._debug_fh.write(f"\n# closed: {_ts()}\n")
            self._debug_fh.close()
            self._debug_fh = None
