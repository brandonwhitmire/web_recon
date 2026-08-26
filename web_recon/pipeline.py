"""Orchestrate Phase 1–3. GET navigation + OPTIONS on start URL. Pastables are never executed."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from web_recon.cache import crawl_key, inventory_path, load_inventory, try_cache
from web_recon.classify import classify_all, count_classes
from web_recon.crawler import PassiveCrawler, php_files_from_pages
from web_recon.models import Config, Fingerprint, ReconResult
from web_recon.report import print_overview, print_phase1, print_phase3, write_all
from web_recon.runlog import RunLog
from web_recon.scope import origin_of, target_slug
from web_recon.term import info, warn
from web_recon.url_tree import LiveUrlTree, format_url_tree
from web_recon.util import detect_attacker_ip, ensure_dir, scan_output_dir


def _emit(result: ReconResult, config: Config, *, from_cache: bool) -> None:
    print_phase3(
        result,
        class_filters=config.class_filters,
        verbose=config.verbose,
        from_cache=from_cache,
    )
    print_overview(result, class_filters=config.class_filters, from_cache=from_cache)


def _maybe_reclassify(result: ReconResult, attacker_ip: str | None) -> ReconResult:
    if attacker_ip == result.attacker_ip or not result.pages:
        return result
    info("Attacker IP changed — refilling pastables from cached pages (no recrawl).")
    result.surfaces = classify_all(
        result.pages,
        origin=result.origin,
        attacker_ip=attacker_ip,
        php_files=result.php_files,
        options_allow=(result.options.allow if result.options else None),
    )
    result.class_counts = count_classes(result.surfaces)
    result.attacker_ip = attacker_ip
    return result


def _ingest_cached_errors(runlog: RunLog, result: ReconResult) -> None:
    seen: set[str] = set()
    for p in result.pages:
        if not p.error:
            continue
        line = f"{p.final_url or p.url}: {p.error}"
        if line in seen:
            continue
        seen.add(line)
        runlog.error(line)


def _print_phase2_tree(host: str, urls: list[str], *, from_cache: bool) -> None:
    extra = " {byellow}[from cache]{rst}" if from_cache else ""
    info("{bblue}Phase 2 {green}(rendered-DOM crawl){rst}" + extra)
    info("{bright}[{yellow}" + host + "{crst}/{bgreen}crawl{crst}]{rst}")
    print(format_url_tree(urls, host))


def _phase1_headers(pages) -> list:
    return pages[0].headers if pages else []


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
    out_dir = scan_output_dir(config.output_root, slug)
    ensure_dir(out_dir / "dom")

    runlog = RunLog(out_dir, debug=config.debug, target=start)
    try:
        return await _run(config, start, parsed, origin, slug, out_dir, runlog)
    except Exception as exc:
        runlog.error(f"fatal: {exc}", exc=exc)
        raise
    finally:
        runlog.close()


async def _run(config: Config, start: str, parsed, origin: str, slug: str, out_dir: Path, runlog: RunLog) -> ReconResult:
    attacker_ip = config.attacker_ip or detect_attacker_ip(start)
    scope_host = (parsed.hostname or "").lower()
    key = crawl_key(config)

    info("Target: {byellow}" + start + "{rst}")
    info("Scope host: {byellow}" + scope_host + "{rst} (subdomains off, GET navigation + OPTIONS)")
    info("Output: {bgreen}" + str(out_dir) + "{rst}")
    if attacker_ip:
        info("Attacker IP (for pastable fill): {byellow}" + attacker_ip + "{rst}")
    else:
        warn("Attacker IP unknown — leaving <ATTACKER_IP> placeholder")
    if config.debug:
        info("Debug log: {bgreen}" + str(runlog.debug_path) + "{rst}")
    runlog.debug(f"start={start} scope={scope_host} attacker_ip={attacker_ip} debug={config.debug}")

    if not config.force_rescan:
        cached = try_cache(out_dir, key)
        if cached:
            runlog.debug("cache hit")
            cached = _maybe_reclassify(cached, attacker_ip)
            _ingest_cached_errors(runlog, cached)
            runlog.write_errors()
            print()
            print_phase1(
                cached.start_url,
                cached.start_headers,
                cached.robots,
                cached.fingerprint,
                cached.sitemap,
                options=cached.options,
                from_cache=True,
            )
            print()
            urls = [p.final_url or p.url for p in cached.pages]
            _print_phase2_tree(cached.target or scope_host, urls, from_cache=True)
            _emit(cached, config, from_cache=True)
            return cached
        existing = load_inventory(inventory_path(out_dir))
        if existing:
            info("Cached inventory found but crawl options differ — rescanning.")
            runlog.debug("cache miss (options differ)")
    else:
        info("{byellow}--force-rescan{rst} — ignoring cache.")
        runlog.debug("force-rescan")

    crawler = PassiveCrawler(
        config,
        scope_host=scope_host,
        origin=origin,
        dom_dir=out_dir / "dom",
        runlog=runlog,
    )
    tree: LiveUrlTree | None = None
    print()
    info(
        "{bblue}Phase 1 {green}(headers, OPTIONS, robots.txt, Wappalyzer, sitemap){rst} "
        "running against {byellow}"
        + start
        + "{rst}"
    )

    def on_phase1(pages) -> None:
        nonlocal tree
        host = (urlparse(crawler.origin).hostname or scope_host).lower()
        print_phase1(
            start,
            _phase1_headers(pages),
            crawler.robots,
            crawler.merged_fingerprint or Fingerprint(),
            crawler.sitemap,
            options=crawler.options,
            include_banner=False,
        )
        print()
        info("{bblue}Phase 2 {green}(rendered-DOM crawl){rst}")
        tree = LiveUrlTree(host)
        info(tree.header_line())
        for line in tree.start_lines():
            print(line)
        for rec in pages:
            for line in tree.add(rec.final_url or rec.url):
                print(line)

    def progress(i: int, total: int, url: str) -> None:
        runlog.debug(f"crawl [{i}/{total}] {url}")
        if tree is None:
            return
        for line in tree.add(url):
            print(line)

    pages = await crawler.crawl([start], progress=progress, on_phase1=on_phase1)
    origin = crawler.origin or origin
    print()
    info("Scope hosts: {byellow}" + (", ".join(sorted(crawler.scope_hosts)) or scope_host) + "{rst}")

    php_files = php_files_from_pages(pages)
    surfaces = classify_all(
        pages,
        origin=origin,
        attacker_ip=attacker_ip,
        php_files=php_files,
        options_allow=(crawler.options.allow if crawler.options else None),
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
            "debug": config.debug,
            "crawl": key,
        },
        start_headers=start_headers,
        options=getattr(crawler, "options", None),
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
    runlog.write_errors()
    _emit(result, config, from_cache=False)
    return result
