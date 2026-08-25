"""Orchestrate Phase 1–3. GET-only. Pastables are written to disk, never executed."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from web_recon.classify import classify_all, count_classes
from web_recon.crawler import PassiveCrawler, php_files_from_pages
from web_recon.models import Config, Fingerprint, ReconResult
from web_recon.report import print_overview, write_all
from web_recon.scope import origin_of, target_slug
from web_recon.util import detect_attacker_ip, ensure_dir


def _progress(i: int, total: int, url: str) -> None:
    print(f"    [{i}/{total}] {url}")


async def run(config: Config) -> ReconResult:
    start = config.start_url.strip()
    if not start.startswith(("http://", "https://")):
        start = "http://" + start
    config.start_url = start

    parsed = urlparse(start)
    if not parsed.hostname:
        raise SystemExit(f"Invalid URL: {start}")

    origin = origin_of(start)
    slug = target_slug(start)
    out_dir = Path(config.output_root) / slug
    dom_dir = ensure_dir(out_dir / "dom")

    attacker_ip = config.attacker_ip or detect_attacker_ip()
    scope_host = (parsed.hostname or "").lower()

    print(f"[*] Target: {start}")
    print(f"[*] Scope host: {scope_host} (subdomains off, GET navigation only)")
    print(f"[*] Output: {out_dir}")
    if attacker_ip:
        print(f"[*] Attacker IP (for pastable fill): {attacker_ip}")
    else:
        print("[*] Attacker IP unknown — leaving <ATTACKER_IP> placeholder")

    crawler = PassiveCrawler(config, scope_host=scope_host, origin=origin, dom_dir=dom_dir)

    print("[*] Phase 1–2: robots.txt, sitemap.xml, rendered-DOM crawl")
    pages = await crawler.crawl([start], progress=_progress)
    origin = crawler.origin or origin
    print(f"[*] Scope hosts: {', '.join(sorted(crawler.scope_hosts)) or scope_host}")

    php_files = php_files_from_pages(pages)
    print(f"[*] Phase 3: classify {sum(1 for _ in pages)} page(s) → input surfaces")
    surfaces = classify_all(
        pages,
        origin=origin,
        attacker_ip=attacker_ip,
        php_files=php_files,
    )
    counts = count_classes(surfaces)

    start_headers = pages[0].headers if pages else []
    result = ReconResult(
        target=scope_host,
        start_url=start,
        origin=origin,
        slug=slug,
        output_dir=str(out_dir),
        config={
            "max_pages": config.max_pages,
            "max_depth": config.max_depth,
            "verbose": config.verbose,
            "enqueue_sitemap": config.enqueue_sitemap,
        },
        start_headers=start_headers,
        robots=getattr(crawler, "robots", None),
        sitemap=getattr(crawler, "sitemap", None),
        fingerprint=getattr(crawler, "merged_fingerprint", None) or Fingerprint(),
        pages=pages,
        surfaces=surfaces,
        class_counts=counts,
        php_files=php_files,
        attacker_ip=attacker_ip,
        errors=[p.error for p in pages if p.error],
    )
    write_all(result, verbose=config.verbose)
    print_overview(result)
    return result
