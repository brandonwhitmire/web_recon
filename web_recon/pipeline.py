"""Orchestrate Phase 1–3. GET-only. Pastables are written to disk, never executed."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from web_recon.cache import crawl_key, inventory_path, load_inventory, try_cache
from web_recon.classify import classify_all, count_classes
from web_recon.crawler import PassiveCrawler, php_files_from_pages
from web_recon.models import Config, Fingerprint, ReconResult
from web_recon.report import print_class_pastables, print_overview, write_all
from web_recon.scope import origin_of, target_slug
from web_recon.term import info, warn
from web_recon.util import detect_attacker_ip, ensure_dir


def _progress(i: int, total: int, url: str) -> None:
    host = urlparse(url).hostname or ""
    info(
        "{bright}[{yellow}"
        + host
        + "{crst}/{bgreen}crawl{crst}]{rst} ["
        + str(i)
        + "/"
        + str(total)
        + "] "
        + url
    )


def _emit(result: ReconResult, config: Config, *, from_cache: bool) -> None:
    print_overview(result, class_filters=config.class_filters, from_cache=from_cache)
    if config.class_filters:
        print_class_pastables(result, config.class_filters, verbose=config.verbose)


def _maybe_reclassify(result: ReconResult, attacker_ip: str | None) -> ReconResult:
    if attacker_ip == result.attacker_ip or not result.pages:
        return result
    info("Attacker IP changed — refilling pastables from cached pages (no recrawl).")
    result.surfaces = classify_all(
        result.pages,
        origin=result.origin,
        attacker_ip=attacker_ip,
        php_files=result.php_files,
    )
    result.class_counts = count_classes(result.surfaces)
    result.attacker_ip = attacker_ip
    return result


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
    ensure_dir(out_dir / "dom")

    attacker_ip = config.attacker_ip or detect_attacker_ip()
    scope_host = (parsed.hostname or "").lower()
    key = crawl_key(config)

    info("Target: {byellow}" + start + "{rst}")
    info("Scope host: {byellow}" + scope_host + "{rst} (subdomains off, GET navigation only)")
    info("Output: {bgreen}" + str(out_dir) + "{rst}")
    if attacker_ip:
        info("Attacker IP (for pastable fill): {byellow}" + attacker_ip + "{rst}")
    else:
        warn("Attacker IP unknown — leaving <ATTACKER_IP> placeholder")

    if not config.force_rescan:
        cached = try_cache(out_dir, key)
        if cached:
            cached = _maybe_reclassify(cached, attacker_ip)
            _emit(cached, config, from_cache=True)
            return cached
        existing = load_inventory(inventory_path(out_dir))
        if existing:
            info("Cached inventory found but crawl options differ — rescanning.")
    else:
        info("{byellow}--force-rescan{rst} — ignoring cache.")

    crawler = PassiveCrawler(config, scope_host=scope_host, origin=origin, dom_dir=out_dir / "dom")

    info(
        "{bblue}Phase 1–2 {green}(robots.txt, sitemap.xml, rendered-DOM crawl){rst} running against {byellow}"
        + start
        + "{rst}"
    )
    pages = await crawler.crawl([start], progress=_progress)
    origin = crawler.origin or origin
    info("Scope hosts: {byellow}" + (", ".join(sorted(crawler.scope_hosts)) or scope_host) + "{rst}")

    php_files = php_files_from_pages(pages)
    info(
        "{bblue}Phase 3 {green}(classify){rst} {byellow}"
        + str(len(pages))
        + "{rst} page(s) on {byellow}"
        + scope_host
        + "{rst}"
    )
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
            "verbose": config.verbose,
            "crawl": key,
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
    _emit(result, config, from_cache=False)
    return result
