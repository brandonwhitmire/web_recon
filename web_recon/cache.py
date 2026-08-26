"""Crawl-result cache. Identity is structured crawl options, not argv order.

Classifier filters (--sqli, --xss, …), --verbose, and --debug are output-only
and do not change the cache key. --force-rescan skips the cache.
"""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from web_recon.models import (
    Fingerprint,
    FormField,
    FormRecord,
    Header,
    OptionsInfo,
    PageRecord,
    ReconResult,
    RobotsInfo,
    SitemapInfo,
    Surface,
    TechHit,
)
from web_recon.scope import origin_of, page_path_of


def normalize_start_url(url: str) -> str:
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    origin = origin_of(url)
    path = page_path_of(url).rstrip("/")
    query = urlparse(url).query
    out = f"{origin}/{path}" if path else origin
    if query:
        out += "?" + query
    return out


def crawl_key(config) -> dict[str, Any]:
    """Options that change what gets crawled. Order-independent."""
    return {
        "start_url": normalize_start_url(config.start_url),
        "max_pages": int(config.max_pages),
        "max_depth": int(config.max_depth),
        "timeout_ms": int(config.timeout_ms),
        "settle_ms": int(config.settle_ms),
        "delay_s": float(config.delay_s),
        "user_agent": config.user_agent or "",
        "tls_verify": bool(config.tls_verify),
        "enqueue_sitemap": bool(config.enqueue_sitemap),
    }


def keys_match(stored: dict[str, Any] | None, current: dict[str, Any]) -> bool:
    if not stored:
        return False
    for k, v in current.items():
        if stored.get(k) != v:
            return False
    return True


def inventory_path(output_dir: str | Path) -> Path:
    return Path(output_dir) / "inventory.json"


def load_inventory(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or "surfaces" not in data:
        return None
    return data


def stored_crawl_key(data: dict[str, Any]) -> dict[str, Any] | None:
    cfg = data.get("config") or {}
    crawl = cfg.get("crawl")
    if isinstance(crawl, dict) and crawl.get("start_url"):
        return crawl
    # Older inventories: reconstruct a partial key.
    start = data.get("start_url")
    if not start:
        return None
    return {
        "start_url": normalize_start_url(str(start)),
        "max_pages": int(cfg.get("max_pages", -1)),
        "max_depth": int(cfg.get("max_depth", -1)),
        "timeout_ms": int(cfg.get("timeout_ms", -1)),
        "settle_ms": int(cfg.get("settle_ms", -1)),
        "delay_s": float(cfg.get("delay_s", -1)),
        "user_agent": str(cfg.get("user_agent", "")),
        "tls_verify": bool(cfg.get("tls_verify", False)),
        "enqueue_sitemap": bool(cfg.get("enqueue_sitemap", True)),
    }


def _take(cls, data: dict[str, Any] | None, **overrides):
    if not data:
        return None
    names = {f.name for f in fields(cls)}
    raw = {k: v for k, v in data.items() if k in names}
    raw.update(overrides)
    return cls(**raw)


def _headers(items: list | None) -> list[Header]:
    out: list[Header] = []
    for h in items or []:
        if isinstance(h, dict):
            out.append(Header(name=h.get("name", ""), value=h.get("value", "")))
    return out


def _tech_hits(items: list | None) -> list[TechHit]:
    out: list[TechHit] = []
    for h in items or []:
        if isinstance(h, dict):
            hit = _take(TechHit, h)
            if hit:
                out.append(hit)
    return out


def _fields(items: list | None) -> list[FormField]:
    out: list[FormField] = []
    for f in items or []:
        if isinstance(f, dict):
            obj = _take(FormField, f)
            if obj:
                out.append(obj)
    return out


def _forms(items: list | None) -> list[FormRecord]:
    out: list[FormRecord] = []
    for f in items or []:
        if not isinstance(f, dict):
            continue
        obj = _take(FormRecord, f, fields=_fields(f.get("fields")))
        if obj:
            out.append(obj)
    return out


def _pages(items: list | None) -> list[PageRecord]:
    out: list[PageRecord] = []
    for p in items or []:
        if not isinstance(p, dict):
            continue
        q = p.get("query_params") or []
        pairs = []
        for item in q:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                pairs.append((str(item[0]), str(item[1])))
        obj = _take(
            PageRecord,
            p,
            headers=_headers(p.get("headers")),
            forms=_forms(p.get("forms")),
            loose_fields=_fields(p.get("loose_fields")),
            query_params=pairs,
        )
        if obj:
            out.append(obj)
    return out


def _surfaces(items: list | None) -> list[Surface]:
    out: list[Surface] = []
    for s in items or []:
        if not isinstance(s, dict):
            continue
        obj = _take(Surface, s)
        if obj:
            out.append(obj)
    return out


def result_from_inventory(data: dict[str, Any], output_dir: str) -> ReconResult:
    fp_raw = data.get("fingerprint") or {}
    fingerprint = Fingerprint(
        hits=_tech_hits(fp_raw.get("hits")),
        os_hints=list(fp_raw.get("os_hints") or []),
        server=fp_raw.get("server"),
        powered_by=fp_raw.get("powered_by"),
        wappalyzer_available=bool(fp_raw.get("wappalyzer_available")),
    )
    robots = _take(RobotsInfo, data.get("robots")) if data.get("robots") else None
    sitemap = _take(SitemapInfo, data.get("sitemap")) if data.get("sitemap") else None
    options = None
    if data.get("options"):
        raw_opt = data["options"]
        options = _take(OptionsInfo, raw_opt, headers=_headers(raw_opt.get("headers") if isinstance(raw_opt, dict) else None))
    return ReconResult(
        target=str(data.get("target") or ""),
        start_url=str(data.get("start_url") or ""),
        origin=str(data.get("origin") or ""),
        slug=str(data.get("slug") or ""),
        output_dir=output_dir,
        config=dict(data.get("config") or {}),
        start_headers=_headers(data.get("start_headers")),
        options=options,
        robots=robots,
        sitemap=sitemap,
        fingerprint=fingerprint,
        pages=_pages(data.get("pages")),
        surfaces=_surfaces(data.get("surfaces")),
        class_counts=dict(data.get("class_counts") or {}),
        php_files=list(data.get("php_files") or []),
        attacker_ip=data.get("attacker_ip"),
        errors=list(data.get("errors") or []),
    )


def try_cache(output_dir: str | Path, current_key: dict[str, Any]) -> ReconResult | None:
    path = inventory_path(output_dir)
    data = load_inventory(path)
    if not data:
        return None
    stored = stored_crawl_key(data)
    if not keys_match(stored, current_key):
        return None
    return result_from_inventory(data, str(output_dir))
