"""CLI for the passive web recon classifier.

Install:  pip install -r requirements.txt && playwright install chromium
Run:      python -m web_recon http://TARGET
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from web_recon import __version__
from web_recon.models import Config
from web_recon.pipeline import run


EPILOG = """
This tool is an enumeration and triage aid for authorized labs (OSCP prep).

It NEVER:
  - submits forms, sends payloads, or probes reflection
  - issues requests beyond GET navigation + robots.txt + sitemap.xml
  - runs sqlmap, nikto, nuclei, ffuf, lfimap, or any other scanner

It PRINTS operator pastables. You copy and run them yourself.

Examples:
  python -m web_recon http://10.10.11.12
  python -m web_recon http://target.web --verbose --attacker-ip 10.10.14.8
  python -m web_recon https://app.lab -o ./results --max-pages 40
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
    p.add_argument("-v", "--verbose", action="store_true", help="Include bypass ladders in classified.md (always written to manual_checks.md)")
    p.add_argument("--max-pages", type=int, default=80, help="Crawl cap (default: 80)")
    p.add_argument("--max-depth", type=int, default=5, help="Max link depth (default: 5)")
    p.add_argument("--timeout", type=int, default=20000, help="Playwright timeout in ms (default: 20000)")
    p.add_argument("--settle-ms", type=int, default=1000, help="Extra DOM settle wait after networkidle (default: 1000)")
    p.add_argument("--delay", type=float, default=0.35, help="Delay between page GETs in seconds (default: 0.35)")
    p.add_argument("--attacker-ip", default=None, help="Fill <ATTACKER_IP> in pastables (default: tun0 if present)")
    p.add_argument("--user-agent", default=None, help="Override User-Agent")
    p.add_argument("--tls-verify", action="store_true", help="Verify TLS certificates (default: off, lab-friendly)")
    p.add_argument("--no-sitemap-crawl", action="store_true", help="List sitemap entries but do not enqueue them")
    p.add_argument("--headed", action="store_true", help="Run Chromium headed (debug)")
    p.add_argument("--version", action="version", version=f"web-recon {__version__}")
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
    )
    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        msg = str(exc)
        print(f"error: {msg}", file=sys.stderr)
        if "Executable doesn't exist" in msg or "playwright" in msg.lower() and "chromium" in msg.lower():
            print("hint: playwright install chromium", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
