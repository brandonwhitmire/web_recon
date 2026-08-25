"""Classifier output filters. Maps CLI flags to PASTABLES class keys."""

from __future__ import annotations

from web_recon_heuristics import PASTABLES

# (cli flag without leading dashes, class key)
# Every PASTABLES class is listed; common aliases included.
FILTER_FLAGS: list[tuple[str, str]] = [
    ("sqli", "sqli"),
    ("xss", "xss"),
    ("ssti", "ssti"),
    ("ssrf", "ssrf"),
    ("xxe", "xxe"),
    ("lfi", "file_inclusion"),
    ("file-inclusion", "file_inclusion"),
    ("cmdi", "command_injection"),
    ("command-injection", "command_injection"),
    ("file-upload", "file_upload"),
    ("idor", "idor"),
    ("verb-tampering", "verb_tampering"),
]

CLASS_KEYS: tuple[str, ...] = tuple(PASTABLES.keys())


def flag_to_class(flag: str) -> str | None:
    flag = flag.lstrip("-").replace("_", "-")
    for cli, key in FILTER_FLAGS:
        if cli == flag:
            return key
    if flag.replace("-", "_") in PASTABLES:
        return flag.replace("-", "_")
    return None


def classes_from_args(args) -> list[str]:
    """Collect unique class keys from argparse namespace (flag order ignored)."""
    seen: set[str] = set()
    out: list[str] = []
    for cli, key in FILTER_FLAGS:
        dest = cli.replace("-", "_")
        if getattr(args, dest, False) and key not in seen:
            seen.add(key)
            out.append(key)
    return out
