"""GET-only Playwright crawler.

Allowed network behavior:
  - page.goto (GET navigation) for in-scope HTML pages
  - APIRequestContext.get for robots.txt and sitemap.xml
  - the page's own subresource loads while rendering (not initiated as extra probes)

Forbidden:
  - form submit, fill, click-to-navigate, type-into-fields
  - POST/PUT/PATCH/DELETE initiated by this tool
  - invoking sqlmap/nikto/ffuf/nuclei/lfimap or any other scanner
  - sending payloads or reflection probes
"""

from __future__ import annotations

import asyncio
from collections import deque
from urllib.parse import urljoin, urlparse

from playwright.async_api import TimeoutError as PlaywrightTimeout
from playwright.async_api import async_playwright

from web_recon.extract import (
    extract_comments,
    extract_forms,
    extract_js_endpoints,
    extract_links,
    extract_loose_fields,
    extract_query_params,
    extract_script_srcs,
    extract_urls_from_text,
    parse_html,
)
from web_recon.fingerprint import fingerprint_page, merge_fingerprints
from web_recon.models import Config, Fingerprint, Header, PageRecord, RobotsInfo, SitemapInfo
from web_recon.scope import (
    crawl_identity,
    in_scope,
    is_cdn_or_third_party,
    is_crawlable_page,
    is_static_asset,
    normalize_url,
    origin_of,
)
from web_recon.runlog import RunLog
from web_recon.util import parse_robots, parse_sitemap_locs, sanitize_filename

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


class PassiveCrawler:
    def __init__(self, config: Config, scope_host: str | set[str], origin: str, dom_dir, runlog: RunLog | None = None):
        self.config = config
        if isinstance(scope_host, str):
            self.scope_hosts = {scope_host.lower()} if scope_host else set()
        else:
            self.scope_hosts = {h.lower() for h in scope_host if h}
        self.origin = origin
        self.dom_dir = dom_dir
        self.runlog = runlog
        self.used_names: set[str] = set()
        self.fingerprints: list[Fingerprint] = []
        self.robots: RobotsInfo | None = None
        self.sitemap: SitemapInfo | None = None
        self.merged_fingerprint: Fingerprint = Fingerprint()

    def _err(self, msg: str, *, exc: BaseException | None = None) -> None:
        if self.runlog:
            self.runlog.error(msg, exc=exc)

    def _dbg(self, msg: str, *, exc: BaseException | None = None) -> None:
        if self.runlog:
            self.runlog.debug(msg, exc=exc)

    async def fetch_text(self, request_ctx, url: str) -> tuple[int | None, str, list[Header], str | None]:
        try:
            kwargs = {
                "timeout": self.config.timeout_ms,
                "max_redirects": 5,
            }
            try:
                resp = await request_ctx.get(url, **kwargs, fail_on_status_code=False)
            except TypeError:
                resp = await request_ctx.get(url, timeout=self.config.timeout_ms)
            body = await resp.text()
            headers = await _headers_from_playwright(resp)
            return resp.status, body, headers, None
        except Exception as exc:
            self._dbg(f"GET {url} failed", exc=exc)
            return None, "", [], str(exc)

    async def fetch_robots(self, request_ctx) -> RobotsInfo:
        url = urljoin(self.origin + "/", "/robots.txt")
        self._dbg(f"GET {url}")
        status, body, _headers, err = await self.fetch_text(request_ctx, url)
        if err:
            info = RobotsInfo(url=url, fetched=False, error=err)
            self._err(f"robots.txt: {err}")
            return info
        if status and status >= 400:
            info = RobotsInfo(url=url, fetched=True, status=status, raw=body, error=f"HTTP {status}")
            self._dbg(f"robots.txt: HTTP {status}")
            return info
        parsed = parse_robots(body, url, status)
        self._dbg(f"robots.txt status={status} disallow={len(parsed.disallow)} sitemaps={len(parsed.sitemaps)}")
        return parsed

    async def fetch_sitemaps(self, request_ctx, extra_sitemap_urls: list[str]) -> SitemapInfo:
        info = SitemapInfo()
        queue: list[str] = []
        default = urljoin(self.origin + "/", "/sitemap.xml")
        for u in [default, *extra_sitemap_urls]:
            n = normalize_url(u, self.origin)
            if n and n not in queue:
                queue.append(n)
        seen_maps: set[str] = set()
        # Cap nested sitemap fetches (GET of sitemap documents only).
        while queue and len(seen_maps) < 10:
            sm_url = queue.pop(0)
            if sm_url in seen_maps:
                continue
            seen_maps.add(sm_url)
            info.requested.append(sm_url)
            self._dbg(f"GET {sm_url}")
            status, body, _headers, err = await self.fetch_text(request_ctx, sm_url)
            if err:
                info.errors.append(f"{sm_url}: {err}")
                self._err(f"sitemap: {sm_url}: {err}")
                continue
            if status and status >= 400:
                info.errors.append(f"{sm_url}: HTTP {status}")
                self._dbg(f"sitemap: {sm_url}: HTTP {status}")
                continue
            if not body.strip():
                info.errors.append(f"{sm_url}: empty")
                self._dbg(f"sitemap: {sm_url}: empty")
                continue
            urls, nested = parse_sitemap_locs(body)
            for loc in urls:
                n = normalize_url(loc, self.origin)
                if n and n not in info.urls:
                    info.urls.append(n)
            for loc in nested:
                n = normalize_url(loc, self.origin)
                if n and n not in seen_maps and n not in queue:
                    queue.append(n)
        return info

    async def visit(self, context, url: str, depth: int) -> PageRecord:
        page = await context.new_page()
        observed: list[str] = []
        js_bodies: list[str] = []

        def _on_request(req) -> None:
            try:
                u = req.url
            except Exception as exc:
                self._dbg("request hook failed", exc=exc)
                return
            n = normalize_url(u)
            if n and in_scope(n, self.scope_hosts) and n not in observed:
                observed.append(n)

        async def _on_response(resp) -> None:
            try:
                url = resp.url
                path = (urlparse(url).path or "").lower()
                ct = ""
                try:
                    ct = (resp.headers or {}).get("content-type", "")
                except Exception:
                    ct = ""
                if "javascript" not in ct.lower() and not path.endswith(".js"):
                    return
                host = (urlparse(url).hostname or "")
                if not in_scope(url, self.scope_hosts) or is_cdn_or_third_party(host):
                    return
                text = await resp.text()
                if text:
                    js_bodies.append(text[:200_000])
            except Exception as exc:
                self._dbg("response hook failed", exc=exc)
                return

        page.on("request", _on_request)
        page.on("response", _on_response)
        if self.runlog and self.runlog.debug_enabled:
            page.on("pageerror", lambda err: self._dbg(f"pageerror {url}: {err}"))
            page.on("requestfailed", lambda req: self._dbg(f"requestfailed {req.url} {req.failure}"))
        rec = PageRecord(url=url, final_url=url, status=None, depth=depth)
        self._dbg(f"visit depth={depth} {url}")
        try:
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=self.config.timeout_ms,
            )
            try:
                await page.wait_for_load_state("networkidle", timeout=self.config.timeout_ms)
            except PlaywrightTimeout:
                pass
            await asyncio.sleep(max(self.config.settle_ms, 0) / 1000.0)
            try:
                await page.evaluate("() => document.readyState")
            except Exception:
                pass

            rec.final_url = page.url
            final_host = (urlparse(rec.final_url).hostname or "").lower()
            if final_host:
                self.scope_hosts.add(final_host)
            if not in_scope(rec.final_url, self.scope_hosts):
                rec.error = f"redirected out of scope to {rec.final_url}"
                rec.out_of_scope.append(rec.final_url)
                self._dbg(f"{url}: {rec.error}")
                return rec

            if response is not None:
                rec.status = response.status
                rec.headers = await _headers_from_playwright(response)
                rec.content_type = (response.headers or {}).get("content-type", "")
            rec.title = await page.title()
            html = await page.content()
            try:
                cookies = await context.cookies(rec.final_url)
                rec.cookies = [{"name": c.get("name", ""), "value": c.get("value", "")[:80]} for c in cookies]
            except Exception:
                rec.cookies = []

            soup = parse_html(html)
            rec.forms = extract_forms(soup, rec.final_url)
            rec.loose_fields = extract_loose_fields(soup)
            rec.query_params = extract_query_params(rec.final_url)
            rec.comments = extract_comments(soup)
            in_links, out_links = extract_links(soup, rec.final_url, self.scope_hosts)
            rec.links = in_links
            rec.out_of_scope = out_links
            rec.js_endpoints = extract_js_endpoints(soup, rec.final_url, self.scope_hosts)
            extra_from_js = extract_urls_from_text(js_bodies, rec.final_url, self.scope_hosts)
            for ep in extra_from_js:
                if ep not in rec.js_endpoints:
                    rec.js_endpoints.append(ep)
            rec.observed_requests = observed
            for u in observed:
                if u not in rec.links and in_scope(u, self.scope_hosts) and is_crawlable_page(u):
                    rec.links.append(u)

            script_srcs = extract_script_srcs(soup, rec.final_url)
            self.fingerprints.append(
                fingerprint_page(rec.final_url, html, rec.headers, rec.cookies, script_srcs)
            )

            fname = sanitize_filename(rec.final_url, self.used_names)
            path = self.dom_dir / fname
            path.write_text(html, encoding="utf-8", errors="replace")
            rec.dom_path = str(path)
            self._dbg(f"  status={rec.status} final={rec.final_url} title={rec.title!r} forms={len(rec.forms)}")
        except PlaywrightTimeout:
            rec.error = f"timeout after {self.config.timeout_ms}ms"
            self._err(f"{url}: {rec.error}")
        except Exception as exc:
            rec.error = str(exc)
            self._err(f"{url}: {rec.error}", exc=exc)
        finally:
            await page.close()
        return rec

    async def crawl(
        self,
        seed_urls: list[str],
        progress=None,
        on_phase1=None,
    ) -> list[PageRecord]:
        cfg = self.config
        pages: list[PageRecord] = []
        seen: set[str] = set()
        q: deque[tuple[str, int]] = deque()
        for u in seed_urls:
            n = normalize_url(u) or u
            ident = crawl_identity(n)
            if ident not in seen:
                seen.add(ident)
                q.append((n, 0))

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=cfg.headless)
            context = await browser.new_context(
                ignore_https_errors=not cfg.tls_verify,
                user_agent=cfg.user_agent or DEFAULT_UA,
                java_script_enabled=True,
                accept_downloads=False,
            )
            context.set_default_timeout(cfg.timeout_ms)

            # Visit the seed first so IP→vhost redirects expand scope_hosts
            # before robots/sitemap enqueue.
            first_seeds: list[tuple[str, int]] = []
            rest: deque[tuple[str, int]] = deque()
            if q:
                first_seeds.append(q.popleft())
                rest = q
                q = deque()

            try:
                for url, depth in first_seeds:
                    rec = await self.visit(context, url, depth)
                    pages.append(rec)
                    seen.add(crawl_identity(rec.final_url or rec.url))
                    if rec.final_url and in_scope(rec.final_url, self.scope_hosts):
                        self.origin = origin_of(rec.final_url) or self.origin
                    for link in rec.links:
                        ident = crawl_identity(link)
                        if ident not in seen and in_scope(link, self.scope_hosts) and is_crawlable_page(link):
                            seen.add(ident)
                            q.append((link, depth + 1))
                    if cfg.delay_s:
                        await asyncio.sleep(cfg.delay_s)

                self.robots = await self.fetch_robots(context.request)
                extra_sitemaps = list(self.robots.sitemaps) if self.robots else []
                self.sitemap = await self.fetch_sitemaps(context.request, extra_sitemaps)
                self.merged_fingerprint = merge_fingerprints(self.fingerprints)
                self._dbg(
                    f"phase1 done pages={len(pages)} robots={bool(self.robots)} "
                    f"sitemap_urls={len(self.sitemap.urls) if self.sitemap else 0}"
                )
                if on_phase1:
                    on_phase1(pages)
                if cfg.enqueue_sitemap:
                    for loc in self.sitemap.urls:
                        if not in_scope(loc, self.scope_hosts):
                            continue
                        if not is_crawlable_page(loc) or is_static_asset(loc):
                            continue
                        ident = crawl_identity(loc)
                        if ident not in seen:
                            seen.add(ident)
                            q.append((loc, 1))

                for item in rest:
                    if crawl_identity(item[0]) not in {crawl_identity(p.final_url or p.url) for p in pages}:
                        q.append(item)

                while q and len(pages) < cfg.max_pages:
                    url, depth = q.popleft()
                    if depth > cfg.max_depth:
                        continue
                    if not in_scope(url, self.scope_hosts):
                        continue
                    if not is_crawlable_page(url):
                        continue
                    if progress:
                        progress(len(pages) + 1, cfg.max_pages, url)
                    rec = await self.visit(context, url, depth)
                    pages.append(rec)
                    if rec.error and "out of scope" in (rec.error or ""):
                        continue
                    for link in rec.links:
                        if not in_scope(link, self.scope_hosts):
                            continue
                        if not is_crawlable_page(link):
                            continue
                        ident = crawl_identity(link)
                        if ident in seen:
                            continue
                        seen.add(ident)
                        q.append((link, depth + 1))
                    if cfg.delay_s:
                        await asyncio.sleep(cfg.delay_s)
            finally:
                await context.close()
                await browser.close()

        self.merged_fingerprint = merge_fingerprints(self.fingerprints)
        return pages


async def _headers_from_playwright(response) -> list[Header]:
    headers: list[Header] = []
    try:
        arr = getattr(response, "headers_array", None)
        if callable(arr):
            arr = arr()
        if asyncio.iscoroutine(arr):
            arr = await arr
        for item in arr or []:
            if isinstance(item, dict):
                headers.append(Header(name=item.get("name", ""), value=item.get("value", "")))
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                headers.append(Header(name=str(item[0]), value=str(item[1])))
        if headers:
            return headers
    except Exception:
        pass
    mapping = getattr(response, "headers", {}) or {}
    if asyncio.iscoroutine(mapping):
        mapping = await mapping
    return _headers_from_mapping(mapping)


def _headers_from_mapping(mapping) -> list[Header]:
    return [Header(name=str(k), value=str(v)) for k, v in dict(mapping).items()]


def php_files_from_pages(pages: list[PageRecord]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for p in pages:
        path = urlparse(p.final_url or p.url).path or ""
        if path.lower().endswith(".php"):
            name = path.lstrip("/")
            if name and name not in seen:
                seen.add(name)
                found.append(name)
        for link in p.links:
            lp = urlparse(link).path or ""
            if lp.lower().endswith(".php"):
                name = lp.lstrip("/")
                if name and name not in seen:
                    seen.add(name)
                    found.append(name)
    return found
