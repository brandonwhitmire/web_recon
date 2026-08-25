"""Parse a fully-rendered DOM for inventory. No requests are made here."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from web_recon.models import FormField, FormRecord
from web_recon.scope import in_scope, is_cdn_or_third_party, normalize_url

SEARCH_NAMES = {"q", "s", "search", "query", "keyword", "keywords", "term", "find"}
XML_NAME_HINTS = ("xml", "soap", "rss", "atom", "svg")
XML_ACCEPT_HINTS = ("xml", "svg", "docx", "xlsx", "odt", "application/xml", "text/xml", "image/svg")

JS_ENDPOINT_PATTERNS = [
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""axios\.\w+\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""\.open\(\s*['"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]\s*,\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""(?:\$|jQuery)\.(?:get|post|ajax)\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""(?:url|href|endpoint|apiUrl|api_url|action)\s*[:=]\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""['"]((?:https?:)?//[^'"]+|/(?:api|ajax|rest|v\d+|cgi-bin)[^'"]*)['"]""", re.I),
    re.compile(r"""['"]([^'"]+\.(?:php|asp|aspx|jsp|cgi|do|pl)(?:\?[^'"]*)?)['"]""", re.I),
    re.compile(r"""(?:window\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""", re.I),
]

FREE_TEXT_TYPES = {"text", "search", "email", "url", "tel", ""}
NON_FREE_TYPES = {"hidden", "checkbox", "radio", "submit", "button", "reset", "image", "file", "range", "color"}


def parse_html(html: str) -> BeautifulSoup:
    return BeautifulSoup(html or "", "lxml")


def _base_href(soup: BeautifulSoup, page_url: str) -> str:
    tag = soup.find("base", href=True)
    if tag:
        return urljoin(page_url, tag["href"])
    return page_url


def extract_comments(soup: BeautifulSoup, limit: int = 200) -> list[str]:
    out: list[str] = []
    for node in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = " ".join((node or "").split())
        if not text:
            continue
        if len(text) > 2000:
            text = text[:2000] + " …[truncated]"
        out.append(text)
        if len(out) >= limit:
            break
    return out


def extract_links(soup: BeautifulSoup, page_url: str, scope_host: str | set[str]) -> tuple[list[str], list[str]]:
    """Return (in_scope_urls, out_of_scope_urls). Includes a/area/iframe/frame/form action/meta refresh."""
    base = _base_href(soup, page_url)
    found: list[str] = []

    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        if href:
            found.append(href)
    for tag in soup.find_all(["iframe", "frame", "embed"]):
        src = tag.get("src")
        if src:
            found.append(src)
    for tag in soup.find_all("form"):
        action = tag.get("action")
        if action is not None:
            found.append(action or page_url)
    for tag in soup.find_all("link", href=True):
        rel = " ".join(tag.get("rel") or []).lower()
        if any(x in rel for x in ("canonical", "alternate", "next", "prev")):
            found.append(tag["href"])
    for tag in soup.find_all("meta", attrs={"http-equiv": True, "content": True}):
        if str(tag.get("http-equiv", "")).lower() == "refresh":
            content = tag.get("content") or ""
            m = re.search(r"url\s*=\s*([^\s;]+)", content, re.I)
            if m:
                found.append(m.group(1).strip("'\""))

    inside: list[str] = []
    outside: list[str] = []
    seen: set[str] = set()
    for raw in found:
        n = normalize_url(raw, base)
        if not n or n in seen:
            continue
        seen.add(n)
        host = (urlparse(n).hostname or "")
        if in_scope(n, scope_host):
            inside.append(n)
        else:
            if host:
                outside.append(n)
    return inside, outside


def _is_search_name(name: str) -> bool:
    n = (name or "").lower()
    if n in SEARCH_NAMES:
        return True
    return "search" in n


def flags_for_field(
    *,
    name: str,
    field_type: str,
    accept: str = "",
    tag_name: str = "input",
    form_enctype: str = "",
    sample_value: str = "",
) -> list[str]:
    flags: set[str] = set()
    n = (name or "").lower()
    itype = (field_type or "").lower()
    accept_l = (accept or "").lower()
    enctype_l = (form_enctype or "").lower()
    tag = (tag_name or "input").lower()

    if itype == "file":
        flags.add("is_file_input")
        if "multipart/form-data" in enctype_l:
            flags.add("is_multipart_form")
        if any(h in accept_l for h in XML_ACCEPT_HINTS):
            flags.add("upload_xml_family")
            flags.add("accepts_xml")

    if tag == "textarea" or itype in FREE_TEXT_TYPES:
        if itype not in NON_FREE_TYPES:
            flags.add("is_free_text")

    if itype == "search" or _is_search_name(n):
        flags.add("is_search_field")
        flags.add("is_free_text")

    if itype == "number" or (sample_value.isdigit() and sample_value != ""):
        flags.add("is_numeric")

    if any(h in n for h in XML_NAME_HINTS) or "xml" in accept_l or "xml" in enctype_l:
        flags.add("accepts_xml")

    return sorted(flags)


def flags_for_query_param(name: str, value: str) -> list[str]:
    """Query strings are not form controls — do not treat every param as free-text XSS/SSTI."""
    flags: set[str] = set()
    n = (name or "").lower()
    if n in SEARCH_NAMES or "search" in n:
        flags.add("is_search_field")
        flags.add("is_free_text")
    if (value or "").isdigit():
        flags.add("is_numeric")
    if any(h in n for h in XML_NAME_HINTS):
        flags.add("accepts_xml")
    return sorted(flags)


def extract_forms(soup: BeautifulSoup, page_url: str) -> list[FormRecord]:
    base = _base_href(soup, page_url)
    forms: list[FormRecord] = []
    for form in soup.find_all("form"):
        action_raw = form.get("action")
        action = normalize_url(action_raw if action_raw is not None else page_url, base) or page_url
        method = (form.get("method") or "get").strip().upper() or "GET"
        enctype = (form.get("enctype") or "application/x-www-form-urlencoded").strip()
        fields: list[FormField] = []
        has_file = False
        controls = form.find_all(["input", "textarea", "select"])
        for el in controls:
            name = (el.get("name") or el.get("id") or "").strip()
            if el.name == "textarea":
                itype = "textarea"
                value = el.text or ""
            elif el.name == "select":
                itype = "select"
                selected = el.find("option", selected=True) or el.find("option")
                value = (selected.get("value") if selected and selected.get("value") is not None else (selected.text if selected else "")) or ""
            else:
                itype = (el.get("type") or "text").strip().lower()
                value = el.get("value") or ""
            accept = el.get("accept") or ""
            if itype == "file":
                has_file = True
            flags = flags_for_field(
                name=name,
                field_type=itype,
                accept=accept,
                tag_name=el.name,
                form_enctype=enctype,
                sample_value=str(value),
            )
            if not name and itype in {"submit", "button", "reset"}:
                continue
            fields.append(
                FormField(
                    name=name or f"(unnamed_{itype})",
                    field_type=itype,
                    value=str(value)[:300],
                    accept=accept,
                    flags=flags,
                )
            )
        forms.append(
            FormRecord(
                action=action,
                method=method,
                enctype=enctype,
                fields=fields,
                has_file_input=has_file,
            )
        )
    return forms


def extract_loose_fields(soup: BeautifulSoup) -> list[FormField]:
    """Inputs not nested in a <form> (JS-controlled)."""
    loose: list[FormField] = []
    for el in soup.find_all(["input", "textarea", "select"]):
        if el.find_parent("form"):
            continue
        name = (el.get("name") or el.get("id") or "").strip()
        if el.name == "textarea":
            itype = "textarea"
            value = el.text or ""
        elif el.name == "select":
            itype = "select"
            value = ""
        else:
            itype = (el.get("type") or "text").strip().lower()
            value = el.get("value") or ""
        if itype in {"submit", "button", "reset"} and not name:
            continue
        accept = el.get("accept") or ""
        flags = flags_for_field(
            name=name,
            field_type=itype,
            accept=accept,
            tag_name=el.name,
            sample_value=str(value),
        )
        if el.get("contenteditable") and str(el.get("contenteditable")).lower() in {"true", ""}:
            flags = sorted(set(flags) | {"is_free_text"})
        loose.append(
            FormField(
                name=name or f"(unnamed_{itype})",
                field_type=itype,
                value=str(value)[:300],
                accept=accept,
                flags=flags,
            )
        )
    for el in soup.find_all(attrs={"contenteditable": True}):
        if el.name in {"input", "textarea"}:
            continue
        val = str(el.get("contenteditable")).lower()
        if val not in {"true", ""}:
            continue
        name = (el.get("id") or el.get("name") or "(contenteditable)").strip()
        loose.append(
            FormField(
                name=name,
                field_type="contenteditable",
                flags=["is_free_text"],
            )
        )
    return loose


def extract_query_params(url: str) -> list[tuple[str, str]]:
    q = urlparse(url).query
    return parse_qsl(q, keep_blank_values=True)


def extract_urls_from_text(blobs: list[str], base_url: str, scope_host: str | set[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for blob in blobs:
        if not blob:
            continue
        chunk = blob if len(blob) < 200_000 else blob[:200_000]
        candidates: list[str] = []
        for rx in JS_ENDPOINT_PATTERNS:
            for m in rx.finditer(chunk):
                candidates.append(m.group(1))
        for raw in candidates:
            raw = raw.strip()
            if not raw or raw.startswith("#") or raw.lower().startswith("javascript:"):
                continue
            n = normalize_url(raw, base_url)
            if not n or n in seen:
                continue
            host = urlparse(n).hostname or ""
            if is_cdn_or_third_party(host):
                continue
            if not in_scope(n, scope_host):
                continue
            seen.add(n)
            found.append(n)
    return found


def extract_js_endpoints(soup: BeautifulSoup, page_url: str, scope_host: str | set[str]) -> list[str]:
    blobs: list[str] = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            blobs.append(src)
        if script.string:
            blobs.append(script.string)
        elif script.get_text():
            blobs.append(script.get_text())
    for tag in soup.find_all(True):
        for attr in ("onclick", "onerror", "onload", "action", "data-url", "data-endpoint", "data-href"):
            val = tag.get(attr)
            if val:
                blobs.append(val)
    return extract_urls_from_text(blobs, _base_href(soup, page_url), scope_host)


def extract_script_srcs(soup: BeautifulSoup, page_url: str) -> list[str]:
    base = _base_href(soup, page_url)
    out = []
    for script in soup.find_all("script", src=True):
        n = normalize_url(script["src"], base)
        if n:
            out.append(n)
    return out
