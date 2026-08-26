"""AutoRecon-style colorized terminal output. Reports on disk stay uncolored.

Prefixes:
  [*]  blue  — info
  [!]  yellow — warn
  [!]  red    — error
  [-]  green  — debug

Inline tokens (same names AutoRecon uses): {bgreen} {byellow} {bblue} {bmagenta}
{bred} {green} {red} {blue} {yellow} {magenta} {bright} {srst} {crst} {rst}
"""

from __future__ import annotations

import os
import sys

# colorama equivalents (Fore / Style)
_FORE = {
    "green": "\033[32m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "yellow": "\033[33m",
    "magenta": "\033[35m",
    "reset": "\033[39m",
}
_BRIGHT = "\033[1m"
_NORMAL = "\033[22m"
_RST = "\033[0m"

TOKENS = {
    "bgreen": _FORE["green"] + _BRIGHT,
    "bred": _FORE["red"] + _BRIGHT,
    "bblue": _FORE["blue"] + _BRIGHT,
    "byellow": _FORE["yellow"] + _BRIGHT,
    "bmagenta": _FORE["magenta"] + _BRIGHT,
    "green": _FORE["green"],
    "red": _FORE["red"],
    "blue": _FORE["blue"],
    "yellow": _FORE["yellow"],
    "magenta": _FORE["magenta"],
    "bright": _BRIGHT,
    "srst": _NORMAL,
    "crst": _FORE["reset"],
    "rst": _NORMAL + _FORE["reset"],
}


def color_enabled(file=None) -> bool:
    stream = file or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def colorize(text: str, *, enabled: bool | None = None, file=None) -> str:
    on = color_enabled(file) if enabled is None else enabled
    out = text
    for name, code in TOKENS.items():
        out = out.replace("{" + name + "}", code if on else "")
    if on and not out.endswith(_RST) and not out.endswith(_FORE["reset"]):
        out += TOKENS["rst"]
    return out


def _prefix(char: str, color_code: str, *, enabled: bool) -> str:
    if not enabled:
        return f"[{char}] "
    return f"{color_code}[{_BRIGHT}{char}{_NORMAL}]{_FORE['reset']} "


def cprint(
    msg: str,
    *,
    color: str = "",
    char: str | None = "*",
    file=sys.stdout,
) -> None:
    on = color_enabled(file)
    prefix = _prefix(char, color, enabled=on) if char is not None else ""
    print(prefix + colorize(msg, enabled=on, file=file), file=file)


def info(msg: str) -> None:
    """AutoRecon info: blue [*]"""
    cprint(msg, color=_FORE["blue"], char="*")


def warn(msg: str) -> None:
    """AutoRecon warn: yellow [!]"""
    cprint(msg, color=_FORE["yellow"], char="!", file=sys.stderr)


def error(msg: str) -> None:
    """AutoRecon error: red [!]"""
    cprint(msg, color=_FORE["red"], char="!", file=sys.stderr)


def debug(msg: str) -> None:
    """AutoRecon debug: green [-]"""
    cprint(msg, color=_FORE["green"], char="-")


def detail(msg: str) -> None:
    """Indented body line with no [*] prefix (headers, tree, robots dump)."""
    on = color_enabled(sys.stdout)
    print("    " + colorize(msg, enabled=on, file=sys.stdout))
