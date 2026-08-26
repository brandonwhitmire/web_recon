"""CLI for the passive web recon classifier.

Install:  pip install -r requirements.txt && playwright install chromium
Run:      python -m web_recon http://TARGET
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import traceback

from web_recon import __version__
from web_recon.filters import FILTER_FLAGS, classes_from_args
from web_recon.models import Config
from web_recon.pipeline import run
from web_recon.term import error, warn


EPILOG = """
This tool is an enumeration and triage aid for authorized labs (OSCP prep).

It NEVER:
  - submits forms, sends payloads, or probes reflection
  - issues requests beyond GET navigation + OPTIONS (start URL) + robots.txt + sitemap.xml
  - runs sqlmap, nikto, nuclei, ffuf, lfimap, or any other scanner

It PRINTS operator pastables. You copy and run them yourself.

Cache:
  Crawl results are reused when the target and crawl options match (flag order
  does not matter). Classifier filters are output-only and do not recrawl.
  Use --force-rescan to ignore the cache.

Examples:
  python -m web_recon http://10.10.11.12
  python -m web_recon http://10.10.11.12 --sqli
  python -m web_recon http://10.10.11.12 --xss --ssti
  python -m web_recon http://10.10.11.12 --lfi --verbose
  python -m web_recon http://10.10.11.12 --force-rescan
  python -m web_recon http://target.web --verbose --attacker-ip 10.10.14.8
  python -m web_recon https://app.lab -o ./results --max-pages 40
  python -m web_recon http://target.web --debug
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web-recon",
        description="Passive web recon & vuln-surface classifier (OSCP-safe).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("url", help="Target URL (http://host[:port][/path])")
    p.add_argument("-o", "--output", default="results", help="Results root directory (default: results)")
    p.add_argument("-v", "--verbose", action="store_true", help="Include bypass ladders in classified.md and Phase 3 terminal output (always written to manual_checks.md)")
    p.add_argument("--max-pages", type=int, default=80, help="Crawl cap (default: 80)")
    p.add_argument("--max-depth", type=int, default=5, help="Max link depth (default: 5)")
    p.add_argument("--timeout", type=int, default=20000, help="Playwright timeout in ms (default: 20000)")
    p.add_argument("--settle-ms", type=int, default=1000, help="Extra DOM settle wait after networkidle (default: 1000)")
    p.add_argument("--delay", type=float, default=0.35, help="Delay between page GETs in seconds (default: 0.35)")
    p.add_argument(
        "--attacker-ip",
        default=None,
        help="Fill <ATTACKER_IP> in pastables (default: local IP used to reach the target, else tun0)",
    )
    p.add_argument("--user-agent", default=None, help="Override User-Agent")
    p.add_argument("--tls-verify", action="store_true", help="Verify TLS certificates (default: off, lab-friendly)")
    p.add_argument("--no-sitemap-crawl", action="store_true", help="List sitemap entries but do not enqueue them")
    p.add_argument("--headed", action="store_true", help="Run Chromium headed (debug)")
    p.add_argument("--force-rescan", action="store_true", help="Ignore cached crawl results and recrawl")
    p.add_argument(
        "--debug",
        action="store_true",
        help="Write debug.log with crawl/request detail (errors always go to errors.log)",
    )
    p.add_argument("--version", action="version", version=f"web-recon {__version__}")

    filt = p.add_argument_group(
        "classifier filters",
        "Output only these classes. Repeatable. Does not recrawl when cache matches.",
    )
    seen_help: dict[str, str] = {
        "sqli": "SQL injection candidate sinks (login / search / id-style)",
        "xss": "XSS candidates",
        "ssti": "SSTI candidates",
        "ssrf": "SSRF candidates",
        "xxe": "XXE candidates",
        "lfi": "File inclusion / LFI (same as --file-inclusion)",
        "file-inclusion": "File inclusion / LFI",
        "cmdi": "Command injection (same as --command-injection)",
        "command-injection": "Command injection",
        "file-upload": "File upload candidates",
        "idor": "IDOR candidates",
        "verb-tampering": "HTTP verb tampering",
    }
    for cli, _key in FILTER_FLAGS:
        filt.add_argument(
            f"--{cli}",
            action="store_true",
            help=seen_help.get(cli, f"Only show {cli} candidates"),
        )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config(
        start_url=args.url,
        output_root=args.output,
        verbose=args.verbose,
        max_pages=max(1, args.max_pages),
        max_depth=max(0, args.max_depth),
        timeout_ms=max(1000, args.timeout),
        settle_ms=max(0, args.settle_ms),
        delay_s=max(0.0, args.delay),
        attacker_ip=args.attacker_ip,
        user_agent=args.user_agent,
        tls_verify=args.tls_verify,
        enqueue_sitemap=not args.no_sitemap_crawl,
        headless=not args.headed,
        force_rescan=args.force_rescan,
        debug=args.debug,
        class_filters=classes_from_args(args),
    )
    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print()
        warn("Interrupted.")
        return 130
    except Exception as exc:
        msg = str(exc)
        error(msg)
        if args.debug:
            traceback.print_exc()
        if "Executable doesn't exist" in msg or ("playwright" in msg.lower() and "chromium" in msg.lower()):
            error("hint: playwright install chromium")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
