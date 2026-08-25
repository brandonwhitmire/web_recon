"""Passive technology fingerprinting from already-fetched HTML, headers, and cookies.

Uses bundled Wappalyzer rules when the optional library is importable. Never fetches
its own copy of the page (update=False). Falls back to local header/cookie/html signatures.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Iterable, Mapping

from web_recon.models import Fingerprint, Header, TechHit

try:
    from Wappalyzer import Wappalyzer, WebPage

    _HAS_WAPPALYZER = True
except Exception:
    _HAS_WAPPALYZER = False
    Wappalyzer = None  # type: ignore
    WebPage = None  # type: ignore

_WAPP_INSTANCE = None

OS_HINTS = [
    (re.compile(r"ubuntu", re.I), "Ubuntu"),
    (re.compile(r"debian", re.I), "Debian"),
    (re.compile(r"centos", re.I), "CentOS"),
    (re.compile(r"red\s?hat|rhel", re.I), "Red Hat"),
    (re.compile(r"fedora", re.I), "Fedora"),
    (re.compile(r"freebsd", re.I), "FreeBSD"),
    (re.compile(r"win64|win32|windows|microsoft", re.I), "Windows"),
    (re.compile(r"darwin|macos", re.I), "macOS"),
]

COOKIE_SIGS: list[tuple[str, str, str]] = [
    ("PHPSESSID", "PHP", "Language"),
    ("wordpress_", "WordPress", "CMS"),
    ("wp-settings", "WordPress", "CMS"),
    ("laravel_session", "Laravel", "Web framework"),
    ("XSRF-TOKEN", "Laravel/Angular-style CSRF cookie", "Web framework"),
    ("JSESSIONID", "Java", "Language"),
    ("ASP.NET_SessionId", "ASP.NET", "Web framework"),
    (".ASPXAUTH", "ASP.NET", "Web framework"),
    ("CAKEPHP", "CakePHP", "Web framework"),
    ("ci_session", "CodeIgniter", "Web framework"),
    ("csrftoken", "Django", "Web framework"),
    ("django", "Django", "Web framework"),
    ("sessionid", "Django (likely)", "Web framework"),
    ("connect.sid", "Express", "Web framework"),
    ("rack.session", "Rack/Rails", "Web framework"),
    ("_tomcat", "Apache Tomcat", "Web server"),
    ("flask", "Flask", "Web framework"),
    ("PLAY_SESSION", "Play Framework", "Web framework"),
    ("JSESSIONID", "Apache Tomcat/Java", "Web server"),
]

HEADER_NAME_SIGS = {
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-drupal-cache": "Drupal",
    "x-generator": "Generator",
    "x-pingback": "WordPress",
    "x-runtime": "Ruby/Rails",
    "x-shopify-stage": "Shopify",
    "x-varnish": "Varnish",
    "cf-ray": "Cloudflare",
    "x-request-id": "Request-ID present",
    "x-amz-cf-id": "Amazon CloudFront",
}

HTML_SIGS: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"wp-content|wp-includes|xmlrpc\.php", re.I), "WordPress", "CMS", "html path"),
    (re.compile(r"Drupal\.settings|sites/default/files", re.I), "Drupal", "CMS", "html path"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js", "JavaScript framework", "html"),
    (re.compile(r"ng-version\s*=", re.I), "Angular", "JavaScript framework", "html"),
    (re.compile(r"data-reactroot|react-root", re.I), "React", "JavaScript framework", "html"),
    (re.compile(r"window\.__NUXT__|__NUXT__", re.I), "Nuxt.js", "JavaScript framework", "html"),
    (re.compile(r"id=\"__vue\"|Vue\.config", re.I), "Vue.js", "JavaScript framework", "html"),
    (re.compile(r"csrf-token|csrfmiddlewaretoken", re.I), "CSRF token field", "Security", "html"),
    (re.compile(r"cgi-bin/", re.I), "CGI", "Language", "html path"),
    (re.compile(r"joomla", re.I), "Joomla", "CMS", "html"),
    (re.compile(r"media/jui/js|com_content", re.I), "Joomla", "CMS", "html path"),
    (re.compile(r"typo3conf|typo3/", re.I), "TYPO3", "CMS", "html"),
]

SCRIPT_SIGS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"jquery[-.](\d+(?:\.\d+)*)", re.I), "jQuery", "JavaScript library"),
    (re.compile(r"jquery(?:\.min)?\.js", re.I), "jQuery", "JavaScript library"),
    (re.compile(r"bootstrap[-.](\d+(?:\.\d+)*)", re.I), "Bootstrap", "UI framework"),
    (re.compile(r"bootstrap(?:\.min)?\.js", re.I), "Bootstrap", "UI framework"),
    (re.compile(r"angular(?:\.min)?\.js", re.I), "AngularJS", "JavaScript framework"),
    (re.compile(r"react(?:\.min)?\.js", re.I), "React", "JavaScript framework"),
    (re.compile(r"vue(?:\.min)?\.js", re.I), "Vue.js", "JavaScript framework"),
    (re.compile(r"moment(?:\.min)?\.js", re.I), "Moment.js", "JavaScript library"),
    (re.compile(r"lodash(?:\.min)?\.js", re.I), "Lodash", "JavaScript library"),
    (re.compile(r"wp-includes/js", re.I), "WordPress", "CMS"),
]


def _wappalyzer() -> object | None:
    global _WAPP_INSTANCE
    if not _HAS_WAPPALYZER:
        return None
    if _WAPP_INSTANCE is None:
        try:
            _WAPP_INSTANCE = Wappalyzer.latest(update=False)
        except Exception:
            _WAPP_INSTANCE = False
    return _WAPP_INSTANCE or None


def headers_to_dict(headers: Iterable[Header] | Mapping[str, str]) -> dict[str, str]:
    if isinstance(headers, Mapping):
        return {str(k): str(v) for k, v in headers.items()}
    out: dict[str, str] = {}
    for h in headers:
        # Last duplicate wins for fingerprint lookup; reports keep the full list.
        out[h.name] = h.value
        out[h.name.lower()] = h.value
    return out


def _header(headers: Mapping[str, str], name: str) -> str | None:
    if name in headers:
        return headers[name]
    low = name.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return None


def fingerprint_page(
    url: str,
    html: str,
    headers: Iterable[Header] | Mapping[str, str],
    cookies: list[dict[str, str]] | None = None,
    script_srcs: list[str] | None = None,
) -> Fingerprint:
    hdrs = headers_to_dict(headers)
    fp = Fingerprint(wappalyzer_available=bool(_wappalyzer()))
    fp.server = _header(hdrs, "Server")
    fp.powered_by = _header(hdrs, "X-Powered-By")
    hits: list[TechHit] = []

    if fp.server:
        hits.append(TechHit("HTTP Server", "Web server", evidence=fp.server, source="header"))
        for rx, name in OS_HINTS:
            if rx.search(fp.server):
                fp.os_hints.append(name)
    if fp.powered_by:
        hits.append(TechHit(fp.powered_by.split("/")[0].strip() or "X-Powered-By", "Language", version=_version_from(fp.powered_by), evidence=f"X-Powered-By: {fp.powered_by}", source="header"))

    for hname, label in HEADER_NAME_SIGS.items():
        val = _header(hdrs, hname)
        if val:
            hits.append(TechHit(label, "Header leak", evidence=f"{hname}: {val}", source="header"))

    gen = None
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html or "", re.I)
    if not m:
        m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', html or "", re.I)
    if m:
        gen = m.group(1)
        hits.append(TechHit(gen.split(" ")[0], "CMS/generator", evidence=f"meta generator: {gen}", source="html"))

    blob = html or ""
    for rx, name, cat, evid in HTML_SIGS:
        if rx.search(blob):
            hits.append(TechHit(name, cat, evidence=evid, source="html"))

    srcs = script_srcs or []
    if not srcs:
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', blob, flags=re.I)
    joined_srcs = " ".join(srcs)
    for rx, name, cat in SCRIPT_SIGS:
        mm = rx.search(joined_srcs)
        if mm:
            ver = mm.group(1) if mm.lastindex else None
            hits.append(TechHit(name, cat, version=ver if ver and ver[0].isdigit() else None, evidence=mm.group(0)[:120], source="script"))

    for cookie in cookies or []:
        cname = cookie.get("name") or ""
        for needle, tech, cat in COOKIE_SIGS:
            if needle.lower() in cname.lower():
                hits.append(TechHit(tech, cat, evidence=f"cookie {cname}", source="cookie"))
                break

    wapp = _wappalyzer()
    if wapp is not None:
        try:
            # Preserve likely original header names for Wappalyzer's header rules.
            w_headers = {_restore_case(k): v for k, v in hdrs.items() if k != k.lower() or k.lower() not in {x.lower() for x in hdrs if x != x.lower()}}
            if not w_headers:
                w_headers = {_restore_case(k): v for k, v in hdrs.items()}
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                page = WebPage(url, html or "", w_headers)
                raw = wapp.analyze_with_versions_and_categories(page)
            for name, info in (raw or {}).items():
                versions = info.get("versions") or []
                cats = info.get("categories") or []
                ver = versions[0] if versions else None
                cat = cats[0] if cats else "Wappalyzer"
                hits.append(TechHit(str(name), str(cat), version=str(ver) if ver else None, evidence="Wappalyzer rule match", source="wappalyzer"))
        except Exception:
            fp.wappalyzer_available = False

    fp.os_hints = _uniq(fp.os_hints)
    fp.hits = _dedupe_hits(hits)
    return fp


def merge_fingerprints(parts: list[Fingerprint]) -> Fingerprint:
    if not parts:
        return Fingerprint()
    merged = Fingerprint(wappalyzer_available=any(p.wappalyzer_available for p in parts))
    hits: list[TechHit] = []
    for p in parts:
        if p.server and not merged.server:
            merged.server = p.server
        if p.powered_by and not merged.powered_by:
            merged.powered_by = p.powered_by
        merged.os_hints.extend(p.os_hints)
        hits.extend(p.hits)
    merged.os_hints = _uniq(merged.os_hints)
    merged.hits = _dedupe_hits(hits)
    return merged


def _version_from(value: str) -> str | None:
    m = re.search(r"(\d+(?:\.\d+)*)", value or "")
    return m.group(1) if m else None


def _restore_case(name: str) -> str:
    known = {
        "server": "Server",
        "x-powered-by": "X-Powered-By",
        "x-aspnet-version": "X-AspNet-Version",
        "x-aspnetmvc-version": "X-AspNetMvc-Version",
        "x-generator": "X-Generator",
        "x-drupal-cache": "X-Drupal-Cache",
        "x-pingback": "X-Pingback",
        "x-runtime": "X-Runtime",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "content-type": "Content-Type",
        "set-cookie": "Set-Cookie",
        "strict-transport-security": "Strict-Transport-Security",
        "content-security-policy": "Content-Security-Policy",
    }
    return known.get(name.lower(), name)


def _uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _dedupe_hits(hits: list[TechHit]) -> list[TechHit]:
    seen: set[tuple[str, str | None, str]] = set()
    out: list[TechHit] = []
    for h in hits:
        key = (h.name.lower(), h.version, h.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out
