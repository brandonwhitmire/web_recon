"""URL scope, normalization, and pseudo-static noise filtering.

Crawl stays on the exact hostname of the target (subdomains off).
External CDNs / third-party hosts are never crawl targets.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse, quote, unquote

# Third-party hosts we never enqueue even if a misconfig widened host matching.
CDN_HOST_MARKERS = (
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "cloudflare.com",
    "cloudflareinsights.com",
    "cdnjs.cloudflare.com",
    "jsdelivr.net",
    "unpkg.com",
    "jquery.com",
    "bootstrapcdn.com",
    "fontawesome.com",
    "fonts.net",
    "typekit.net",
    "akamaihd.net",
    "akamaized.net",
    "fastly.net",
    "cloudfront.net",
    "fbcdn.net",
    "facebook.net",
    "facebook.com",
    "twitter.com",
    "twimg.com",
    "linkedin.com",
    "gravatar.com",
    "github.com",
    "githubusercontent.com",
    "youtube.com",
    "ytimg.com",
    "doubleclick.net",
    "googletagmanager.com",
    "google-analytics.com",
    "hotjar.com",
    "newrelic.com",
    "nr-data.net",
    "sentry.io",
    "segment.com",
    "mixpanel.com",
    "cloudinary.com",
    "imgix.net",
    "w3.org",
    "schema.org",
)

SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "blob", "about", "ws", "wss"}

# Do not *crawl* these as HTML pages (still recorded as out-of-band resources).
STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".cjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm", ".ogg",
    ".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".bz2",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".iso", ".dmg",
}

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "gclid", "dclid", "fbclid", "msclkid", "mc_cid", "mc_eid",
    "igshid", "mkt_tok", "_ga", "_gl", "ref", "ref_src",
}

CACHEBUSTER_NAMES = {"_", "cb", "cachebust", "cachebuster", "nocache", "ts", "t", "v", "ver", "version"}
TIMESTAMP_RE = re.compile(r"^\d{10,13}$")

SPA_FRAGMENT_RE = re.compile(r"^[#][!/]")


def origin_of(url: str) -> str:
    p = urlparse(url)
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    port = p.port
    if not host:
        return ""
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    return f"{scheme}://{netloc}"


def target_slug(url: str) -> str:
    p = urlparse(url)
    host = (p.hostname or "target").lower()
    host = host.replace(":", "_")
    if p.port and p.port not in (80, 443):
        return f"{host}_{p.port}"
    return host


def page_path_of(url: str) -> str:
    """Path relative to origin, no leading slash, no query/fragment. Root is empty."""
    p = urlparse(url)
    path = unquote(p.path or "/")
    if not path or path == "/":
        return ""
    return path.lstrip("/")


def is_cdn_or_third_party(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    if not h:
        return True
    for marker in CDN_HOST_MARKERS:
        if h == marker or h.endswith("." + marker):
            return True
    return False


def scope_hosts_of(host: str | set[str] | None) -> set[str]:
    if host is None:
        return set()
    if isinstance(host, str):
        return {host.lower()} if host else set()
    return {h.lower() for h in host if h}


def in_scope(url: str, scope_host: str | set[str]) -> bool:
    """Exact hostname match (subdomains off). IPs and names compared literally."""
    try:
        p = urlparse(url)
    except Exception:
        return False
    scheme = (p.scheme or "").lower()
    if scheme in SKIP_SCHEMES or not scheme.startswith("http"):
        return False
    host = (p.hostname or "").lower()
    if not host:
        return False
    if is_cdn_or_third_party(host):
        return False
    return host in scope_hosts_of(scope_host)


def is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    if "." not in path.rsplit("/", 1)[-1]:
        return False
    _, _, last = path.rpartition("/")
    if "." not in last:
        return False
    ext = "." + last.rsplit(".", 1)[-1]
    return ext in STATIC_EXTENSIONS


def _is_noise_param(name: str, value: str) -> bool:
    n = name.lower()
    if n in TRACKING_PARAMS:
        return True
    if n in CACHEBUSTER_NAMES and TIMESTAMP_RE.match(value or ""):
        return True
    if n in {"_", "cb", "cachebust", "cachebuster", "nocache"}:
        return True
    return False


def significant_query(url: str) -> tuple[tuple[str, str], ...]:
    q = urlparse(url).query
    pairs = []
    for k, v in parse_qsl(q, keep_blank_values=True):
        if _is_noise_param(k, v):
            continue
        pairs.append((k, v))
    pairs.sort()
    return tuple(pairs)


def should_keep_fragment(fragment: str) -> bool:
    if not fragment:
        return False
    f = fragment if fragment.startswith("#") else f"#{fragment}"
    return bool(SPA_FRAGMENT_RE.match(f))


def normalize_url(url: str, base: str | None = None) -> str | None:
    """Resolve, drop tracking noise, drop on-page anchors, canonicalize."""
    if not url:
        return None
    url = url.strip()
    if not url:
        return None
    if base:
        url = urljoin(base, url)
    try:
        url, frag = urldefrag(url)
        parsed = urlparse(url)
    except Exception:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme in SKIP_SCHEMES:
        return None
    if not scheme.startswith("http"):
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    kept = significant_query(url)
    query = "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in kept)
    rebuilt = urlunparse((scheme, netloc, path, "", query, ""))
    if frag and should_keep_fragment(frag):
        rebuilt = rebuilt + "#" + frag.lstrip("#")
    return rebuilt


def crawl_identity(url: str) -> str:
    """Dedup key: normalized URL without fragment unless SPA-like."""
    n = normalize_url(url)
    return n or url


def is_crawlable_page(url: str) -> bool:
    if is_static_asset(url):
        return False
    p = urlparse(url)
    if (p.scheme or "").lower() not in {"http", "https"}:
        return False
    return True
