from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Config:
    start_url: str
    output_root: str = "results"
    verbose: bool = False
    max_pages: int = 80
    max_depth: int = 5
    timeout_ms: int = 20000
    settle_ms: int = 1000
    delay_s: float = 0.35
    attacker_ip: str | None = None
    user_agent: str | None = None
    tls_verify: bool = False
    enqueue_sitemap: bool = True
    headless: bool = True
    force_rescan: bool = False
    class_filters: list[str] = field(default_factory=list)


@dataclass
class Header:
    name: str
    value: str


@dataclass
class RobotsInfo:
    url: str
    fetched: bool
    status: int | None = None
    raw: str = ""
    user_agents: list[str] = field(default_factory=list)
    disallow: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class SitemapInfo:
    requested: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class TechHit:
    name: str
    category: str
    version: str | None = None
    evidence: str = ""
    source: str = ""  # header | cookie | html | script | wappalyzer


@dataclass
class Fingerprint:
    hits: list[TechHit] = field(default_factory=list)
    os_hints: list[str] = field(default_factory=list)
    server: str | None = None
    powered_by: str | None = None
    wappalyzer_available: bool = False


@dataclass
class FormField:
    name: str
    field_type: str
    value: str = ""
    accept: str = ""
    flags: list[str] = field(default_factory=list)


@dataclass
class FormRecord:
    action: str
    method: str
    enctype: str
    fields: list[FormField] = field(default_factory=list)
    has_file_input: bool = False


@dataclass
class PageRecord:
    url: str
    final_url: str
    status: int | None
    title: str = ""
    content_type: str = ""
    headers: list[Header] = field(default_factory=list)
    cookies: list[dict[str, str]] = field(default_factory=list)
    forms: list[FormRecord] = field(default_factory=list)
    loose_fields: list[FormField] = field(default_factory=list)
    query_params: list[tuple[str, str]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    observed_requests: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    dom_path: str | None = None
    error: str | None = None
    depth: int = 0


@dataclass
class Surface:
    id: str
    kind: str  # query_param | form_field | js_param | site
    page_url: str
    page_path: str
    method: str
    param: str
    sample_value: str = ""
    field_type: str = ""
    context_flags: list[str] = field(default_factory=list)
    evidence: str = ""
    classes: list[str] = field(default_factory=list)
    why: dict[str, str] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)
    canonical: dict[str, list[str]] = field(default_factory=dict)
    verbose: dict[str, list[str]] = field(default_factory=dict)
    reflection_classes: list[str] = field(default_factory=list)
    sqli_priority: str = ""  # HIGH | MEDIUM | ""
    sqli_role: str = ""  # login | search | id | filter | login_adjacent | newsletter | comment


@dataclass
class ReconResult:
    target: str
    start_url: str
    origin: str
    slug: str
    output_dir: str
    config: dict[str, Any] = field(default_factory=dict)
    start_headers: list[Header] = field(default_factory=list)
    robots: RobotsInfo | None = None
    sitemap: SitemapInfo | None = None
    fingerprint: Fingerprint = field(default_factory=Fingerprint)
    pages: list[PageRecord] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)
    class_counts: dict[str, int] = field(default_factory=dict)
    php_files: list[str] = field(default_factory=list)
    attacker_ip: str | None = None
    errors: list[str] = field(default_factory=list)
