"""AutoRecon-style report writers. Markdown + JSON + console overview."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from web_recon.classify import _priority
from web_recon.models import Fingerprint, Header, ReconResult, RobotsInfo, SitemapInfo, Surface
from web_recon.term import detail, info

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


SITEMAP_PRINT_CAP = 40
HEADER_VALUE_MAX = 240


def print_phase1(
    start_url: str,
    headers: list[Header],
    robots: RobotsInfo | None,
    fingerprint: Fingerprint,
    sitemap: SitemapInfo | None,
    *,
    from_cache: bool = False,
    include_banner: bool = True,
) -> None:
    """Terminal Phase 1: headers, robots.txt, Wappalyzer, sitemap (last)."""
    if include_banner:
        extra = " {byellow}[from cache]{rst}" if from_cache else ""
        info(
            "{bblue}Phase 1 {green}(headers, robots.txt, Wappalyzer, sitemap){rst} "
            "running against {byellow}"
            + start_url
            + "{rst}"
            + extra
        )
    _print_headers_block(headers)
    _print_robots_block(robots)
    _print_wappalyzer_block(fingerprint)
    _print_sitemap_block(sitemap)


def _print_headers_block(headers: list[Header]) -> None:
    info("HTTP headers")
    if not headers:
        detail("(none captured)")
        return
    for h in headers:
        val = h.value or ""
        if len(val) > HEADER_VALUE_MAX:
            val = val[:HEADER_VALUE_MAX] + "…"
        detail(f"{h.name}: {val}")
    present = {h.name.lower() for h in headers}
    missing = [n for n in SECURITY_HEADERS if n.lower() not in present]
    if missing:
        detail("missing security headers: " + ", ".join(missing))


def _print_robots_block(robots: RobotsInfo | None) -> None:
    info("robots.txt")
    if not robots:
        detail("(not fetched)")
        return
    status = f"status={robots.status}" if robots.status is not None else "not fetched"
    detail(robots.url + "  " + status)
    if robots.error:
        detail("error: " + robots.error)
    if robots.user_agents:
        detail("User-agent: " + ", ".join(robots.user_agents))
    if robots.disallow:
        for d in robots.disallow:
            detail("Disallow: " + d)
    else:
        detail("Disallow: (none)")
    if robots.allow:
        for a in robots.allow:
            detail("Allow: " + a)
    if robots.sitemaps:
        for s in robots.sitemaps:
            detail("Sitemap: " + s)
    raw_lines = (robots.raw or "").rstrip().splitlines()
    if raw_lines and len(raw_lines) <= 30:
        detail("---")
        for line in raw_lines:
            detail(line)


def _print_wappalyzer_block(fp: Fingerprint) -> None:
    info("Wappalyzer")
    if fp.wappalyzer_available:
        detail("library: loaded")
    else:
        detail("library: not installed (header/cookie/html signatures only)")
    if fp.server:
        detail("Server: " + fp.server)
    if fp.powered_by:
        detail("X-Powered-By: " + fp.powered_by)
    if fp.os_hints:
        detail("OS hints: " + ", ".join(fp.os_hints))
    if not fp.hits:
        detail("(no technology signatures matched)")
        return
    for h in fp.hits:
        ver = f" {h.version}" if h.version else ""
        src = f"  [{h.source}]" if h.source else ""
        detail(f"{h.name}{ver}  ({h.category}){src}")


def _print_sitemap_block(sitemap: SitemapInfo | None) -> None:
    info("sitemap.xml")
    if not sitemap:
        detail("(not fetched)")
        return
    if sitemap.requested:
        for u in sitemap.requested:
            detail("requested: " + u)
    urls = list(sitemap.urls or [])
    detail(f"entries: {len(urls)}")
    if not urls:
        detail("(none)")
    else:
        shown = urls[:SITEMAP_PRINT_CAP]
        for u in shown:
            detail(u)
        extra = len(urls) - len(shown)
        if extra > 0:
            detail(f"… +{extra} more (see summary.md)")
    if sitemap.errors:
        for e in sitemap.errors:
            detail("error: " + e)


def _display_path(s: Surface) -> str:
    path = s.page_path or "/"
    if path == "":
        return "/"
    if not str(path).startswith("/"):
        return "/" + path
    return path


def _sqli_sort_key(s: Surface) -> tuple:
    role_rank = {
        "login": 0,
        "search": 1,
        "id": 2,
        "filter": 3,
        "login_adjacent": 4,
        "newsletter": 5,
        "comment": 6,
    }
    return (role_rank.get(s.sqli_role, 9), s.page_path, s.param.lower())


def fence(text: str) -> str:
    body = text if isinstance(text, str) else str(text)
    ticks = "```"
    while ticks in body:
        ticks += "`"
    return f"{ticks}\n{body}\n{ticks}"


def _header_map(headers: list[Header]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for h in headers:
        out[h.name.lower()].append(h.value)
    return out


def write_all(result: ReconResult, verbose: bool) -> None:
    out = Path(result.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text(render_summary(result), encoding="utf-8")
    (out / "crawl_map.md").write_text(render_crawl_map(result), encoding="utf-8")
    (out / "classified.md").write_text(render_classified(result, include_verbose=verbose), encoding="utf-8")
    (out / "manual_checks.md").write_text(render_manual_checks(result), encoding="utf-8")
    (out / "inventory.json").write_text(render_inventory(result), encoding="utf-8")


def render_summary(result: ReconResult) -> str:
    lines: list[str] = []
    lines.append(f"# Page summary / fingerprint — {result.target}")
    lines.append("")
    lines.append(f"- Start URL: `{result.start_url}`")
    lines.append(f"- Origin: `{result.origin}`")
    lines.append(f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}")
    lines.append("- Mode: **passive** (GET navigation + robots.txt + sitemap.xml). No exploitation, no payload send.")
    lines.append("")
    lines.append("## HTTP response headers (start page)")
    lines.append("")
    if result.start_headers:
        lines.append(fence("\n".join(f"{h.name}: {h.value}" for h in result.start_headers)))
    else:
        lines.append("_No headers captured (navigation failed)._")
    lines.append("")
    lines.append("### Security headers glance")
    lines.append("")
    present = _header_map(result.start_headers)
    for name in SECURITY_HEADERS:
        vals = present.get(name.lower())
        if vals:
            lines.append(f"- **{name}:** {' | '.join(vals)}")
        else:
            lines.append(f"- **{name}:** MISSING")
    leaks = []
    for key in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if key in present:
            leaks.append(f"{key}: {present[key][0]}")
    lines.append("")
    lines.append("### Framework / server leaks")
    lines.append("")
    if leaks:
        for item in leaks:
            lines.append(f"- `{item}`")
    else:
        lines.append("- None beyond the raw header dump above.")
    lines.append("")
    lines.append("## robots.txt")
    lines.append("")
    rob = result.robots
    if not rob:
        lines.append("_Not fetched._")
    else:
        lines.append(f"- URL: `{rob.url}`")
        lines.append(f"- Fetched: `{rob.fetched}` status={rob.status!s}")
        if rob.error:
            lines.append(f"- Note: {rob.error}")
        if rob.user_agents:
            lines.append(f"- User-agent: {', '.join(f'`{u}`' for u in rob.user_agents)}")
        if rob.disallow:
            lines.append("- Disallow:")
            for d in rob.disallow:
                lines.append(f"  - `{d}`")
        else:
            lines.append("- Disallow: _(none)_")
        if rob.allow:
            lines.append("- Allow:")
            for a in rob.allow:
                lines.append(f"  - `{a}`")
        if rob.sitemaps:
            lines.append("- Sitemap directives:")
            for s in rob.sitemaps:
                lines.append(f"  - `{s}`")
        if rob.other:
            lines.append("- Other:")
            for o in rob.other:
                lines.append(f"  - `{o}`")
        if rob.raw:
            lines.append("")
            lines.append("### Raw")
            lines.append("")
            lines.append(fence(rob.raw.rstrip() or "(empty)"))
    lines.append("")
    lines.append("## sitemap.xml")
    lines.append("")
    sm = result.sitemap
    if not sm:
        lines.append("_Not fetched._")
    else:
        if sm.requested:
            lines.append("- Requested:")
            for u in sm.requested:
                lines.append(f"  - `{u}`")
        if sm.urls:
            lines.append(f"- Entries ({len(sm.urls)}):")
            for u in sm.urls:
                lines.append(f"  - `{u}`")
        else:
            lines.append("- Entries: _(none)_")
        if sm.errors:
            lines.append("- Errors:")
            for e in sm.errors:
                lines.append(f"  - {e}")
    lines.append("")
    lines.append("## Tech fingerprint")
    lines.append("")
    lines.extend(_fingerprint_md(result.fingerprint))
    lines.append("")
    lines.append("_Nikto is intentionally not run. Header + tech dump above is the useful subset._")
    lines.append("")
    return "\n".join(lines)


def _fingerprint_md(fp: Fingerprint) -> list[str]:
    lines = []
    lines.append(f"- Wappalyzer library loaded: `{fp.wappalyzer_available}`")
    if fp.server:
        lines.append(f"- Server: `{fp.server}`")
    if fp.powered_by:
        lines.append(f"- X-Powered-By: `{fp.powered_by}`")
    if fp.os_hints:
        lines.append(f"- OS hints: {', '.join(f'`{x}`' for x in fp.os_hints)}")
    else:
        lines.append("- OS hints: _(none)_")
    lines.append("")
    if not fp.hits:
        lines.append("_No technology signatures matched._")
        return lines
    lines.append("| Technology | Category | Version | Source | Evidence |")
    lines.append("|---|---|---|---|---|")
    for h in fp.hits:
        evid = (h.evidence or "").replace("|", "\\|")[:160]
        lines.append(f"| {h.name} | {h.category} | {h.version or ''} | {h.source} | {evid} |")
    return lines


def render_crawl_map(result: ReconResult) -> str:
    lines: list[str] = []
    lines.append(f"# Crawl map — {result.target}")
    lines.append("")
    lines.append(f"- Pages visited: **{len(result.pages)}**")
    lines.append(f"- Input surfaces: **{len(result.surfaces)}**")
    lines.append("- Crawl: same host only, rendered DOM, GET navigation. Subdomains off. No dirbust.")
    lines.append("")
    lines.append("## Discovered URLs")
    lines.append("")
    seen_urls: list[str] = []
    for p in result.pages:
        u = p.final_url or p.url
        if u not in seen_urls:
            seen_urls.append(u)
        for link in p.links:
            if link not in seen_urls:
                seen_urls.append(link)
    for u in seen_urls:
        lines.append(f"- `{u}`")
    if not seen_urls:
        lines.append("- _(none)_")
    lines.append("")
    lines.append("## robots.txt Disallow paths (listed, not auto-crawled)")
    lines.append("")
    if result.robots and result.robots.disallow:
        for d in result.robots.disallow:
            lines.append(f"- `{d}`")
        lines.append("")
        lines.append("_These are operator hints (often juicy). This tool does not GET them unless linked from in-scope pages or sitemap._")
    else:
        lines.append("- _(none)_")
    lines.append("")

    for p in result.pages:
        url = p.final_url or p.url
        lines.append(f"## {url}")
        lines.append("")
        meta = f"status={p.status!s} depth={p.depth} title={p.title!r}"
        if p.dom_path:
            meta += f" dom=`{p.dom_path}`"
        lines.append(f"- {meta}")
        if p.error:
            lines.append(f"- error: {p.error}")
        if p.query_params:
            lines.append("- query params:")
            for n, v in p.query_params:
                lines.append(f"  - `{n}` = `{v}`")
        if p.forms:
            lines.append("- forms:")
            for i, form in enumerate(p.forms, 1):
                lines.append(f"  - form {i}: `{form.method} {form.action}` enctype=`{form.enctype}`")
                for field in form.fields:
                    flags = ",".join(field.flags) if field.flags else ""
                    extra = f" flags={flags}" if flags else ""
                    lines.append(f"    - `{field.field_type}` `{field.name}` value=`{field.value}`{extra}")
        if p.loose_fields:
            lines.append("- DOM inputs (no form):")
            for field in p.loose_fields:
                flags = ",".join(field.flags) if field.flags else ""
                lines.append(f"  - `{field.field_type}` `{field.name}` flags={flags}")
        if p.js_endpoints:
            lines.append("- JS-referenced endpoints:")
            for ep in p.js_endpoints:
                lines.append(f"  - `{ep}`")
        if p.comments:
            lines.append("- HTML comments:")
            for c in p.comments:
                lines.append(f"  - {fence(c)}")
        if p.out_of_scope:
            lines.append(f"- out-of-scope links (first 15 of {len(p.out_of_scope)}):")
            for u in p.out_of_scope[:15]:
                lines.append(f"  - `{u}`")
        lines.append("")
    return "\n".join(lines)


def render_classified(result: ReconResult, include_verbose: bool) -> str:
    lines: list[str] = []
    lines.append(f"# Classified input surfaces — {result.target}")
    lines.append("")
    lines.append("Candidate classes only. **Nothing here is a confirmed vulnerability.**")
    lines.append("This tool did not submit forms, send payloads, or run scanners.")
    lines.append("Paste commands into your own terminal / proxy. Emit, never execute.")
    lines.append("")
    lines.append("## Counts")
    lines.append("")
    if result.class_counts:
        for cls, n in result.class_counts.items():
            lines.append(f"- **{cls}:** {n}")
    else:
        lines.append("- _(no candidate classes)_")
    lines.append("")
    lines.append("## SQLi Candidate Surfaces")
    lines.append("")
    lines.append(
        "Auth and DB-lookup inputs only (login, search, id-style GET). "
        "Not cookies, headers, uploads, or unrelated free-text. "
        "**Candidate sinks** — this tool did not send payloads or submit forms."
    )
    lines.append("")
    sqli_surfs = [s for s in result.surfaces if "sqli" in s.classes]
    high = sorted([s for s in sqli_surfs if s.sqli_priority == "HIGH"], key=_sqli_sort_key)
    medium = sorted([s for s in sqli_surfs if s.sqli_priority == "MEDIUM"], key=_sqli_sort_key)
    if not sqli_surfs:
        lines.append("_No HIGH/MEDIUM SQLi candidate sinks._")
        lines.append("")
    else:
        for label, group in (("HIGH", high), ("MEDIUM", medium)):
            lines.append(f"### {label}")
            lines.append("")
            if not group:
                lines.append("_None._")
                lines.append("")
                continue
            for s in group:
                _sqli_sink_md(lines, s, include_verbose=include_verbose)
    lines.append("## Surfaces")
    lines.append("")
    classified = [s for s in result.surfaces if s.classes]
    unclassified = [s for s in result.surfaces if not s.classes]
    for s in classified:
        _surface_md(lines, s, include_verbose=include_verbose)
    if unclassified:
        lines.append("## Unclassified inventory (no heuristic match)")
        lines.append("")
        for s in unclassified:
            if s.kind == "site":
                continue
            lines.append(f"- `{s.method} /{s.page_path}` param=`{s.param}` ({s.kind})")
        lines.append("")
    return "\n".join(lines)


def _sqli_sink_md(lines: list[str], s: Surface, include_verbose: bool) -> None:
    display = _display_path(s)
    lines.append(f"#### {s.method} {display}  `{s.param}`")
    lines.append("")
    if s.kind == "form_field":
        lines.append(f"- Location: `{s.method}` form action=`{s.page_url}` field=`{s.param}`")
    else:
        lines.append(f"- Location: `{s.method}` `{s.page_url}` param=`{s.param}`")
    lines.append(f"- Priority: **{s.sqli_priority or 'n/a'}**")
    if s.sqli_role:
        lines.append(f"- Role: `{s.sqli_role}`")
    if s.why.get("sqli"):
        lines.append(f"- Why: {s.why['sqli']}")
    if s.notes.get("sqli"):
        lines.append(f"- Note: {s.notes['sqli']}")
    lines.append("")
    cmds = list(s.canonical.get("sqli") or [])
    if include_verbose:
        cmds.extend(s.verbose.get("sqli") or [])
    if cmds:
        lines.append(fence("\n".join(cmds)))
        lines.append("")
    else:
        lines.append("_No SQLi pastables for this sink._")
        lines.append("")


def _surface_md(lines: list[str], s: Surface, include_verbose: bool) -> None:
    display = _display_path(s)
    lines.append(f"### {s.method} {display}  `{s.param}`")
    lines.append("")
    lines.append(f"- Kind: `{s.kind}`")
    lines.append(f"- Page: `{s.page_url}`")
    lines.append(f"- Param: `{s.param}`")
    if s.field_type:
        lines.append(f"- Field type: `{s.field_type}`")
    if s.sample_value:
        lines.append(f"- Sample value: `{s.sample_value}`")
    if s.context_flags:
        lines.append(f"- Flags: {', '.join(f'`{f}`' for f in s.context_flags)}")
    if s.evidence:
        lines.append(f"- Evidence: {s.evidence}")
    lines.append(f"- Candidates: {', '.join(f'`{c}`' for c in s.classes)}")
    if s.reflection_classes:
        lines.append(
            "- Reflection: " + ", ".join(s.reflection_classes)
            + " — manually confirm this reflects in the response (Page Source vs Inspect Element)."
        )
    lines.append("")
    for cls in s.classes:
        lines.append(f"#### {cls}")
        lines.append("")
        if cls == "sqli":
            if s.sqli_priority:
                lines.append(f"- Priority: **{s.sqli_priority}**")
            if s.why.get(cls):
                lines.append(f"- Why: {s.why[cls]}")
            lines.append("- Pastables: see **SQLi Candidate Surfaces** above.")
            lines.append("")
            continue
        if s.why.get(cls):
            lines.append(f"- Why: {s.why[cls]}")
        if s.notes.get(cls):
            lines.append(f"- Note: {s.notes[cls]}")
        lines.append("")
        cmds = list(s.canonical.get(cls) or [])
        if include_verbose:
            cmds.extend(s.verbose.get(cls) or [])
        if cmds:
            lines.append(fence("\n".join(cmds)))
            lines.append("")
        else:
            lines.append("_No pastable template for this class._")
            lines.append("")


def render_manual_checks(result: ReconResult) -> str:
    lines: list[str] = []
    lines.append(f"# Manual checks / bypass ladders — {result.target}")
    lines.append("")
    lines.append("Verbose variants **not** shown in the default classified report.")
    lines.append("Operator-run only. This tool never executes these commands.")
    lines.append("")
    any_verbose = False
    for s in result.surfaces:
        blocks = [(cls, s.verbose.get(cls) or []) for cls in s.classes]
        blocks = [(c, cmds) for c, cmds in blocks if cmds]
        if not blocks:
            continue
        any_verbose = True
        display = _display_path(s)
        lines.append(f"## {s.method} {display} `{s.param}`")
        lines.append("")
        for cls, cmds in blocks:
            lines.append(f"### {cls}")
            lines.append("")
            if s.notes.get(cls):
                lines.append(f"- {s.notes[cls]}")
                lines.append("")
            lines.append(fence("\n".join(cmds)))
            lines.append("")
    if not any_verbose:
        lines.append("_No verbose bypass templates matched any surface._")
        lines.append("")
    return "\n".join(lines)


def render_inventory(result: ReconResult) -> str:
    payload = {
        "policy": {
            "mode": "passive",
            "exploitation": False,
            "confirmation": False,
            "requests_allowed": "GET navigation, robots.txt, sitemap.xml, render subresources",
            "pastables": "emitted as text, never executed",
        },
        "target": result.target,
        "start_url": result.start_url,
        "origin": result.origin,
        "slug": result.slug,
        "output_dir": result.output_dir,
        "attacker_ip": result.attacker_ip,
        "class_counts": result.class_counts,
        "config": result.config,
        "fingerprint": asdict(result.fingerprint),
        "robots": asdict(result.robots) if result.robots else None,
        "sitemap": asdict(result.sitemap) if result.sitemap else None,
        "start_headers": [asdict(h) for h in result.start_headers],
        "pages": [asdict(p) for p in result.pages],
        "surfaces": [asdict(s) for s in result.surfaces],
        "php_files": result.php_files,
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def print_overview(result: ReconResult, class_filters: list[str] | None = None, from_cache: bool = False) -> None:
    filters = set(class_filters or [])
    surfaces = result.surfaces
    if filters:
        surfaces = [s for s in surfaces if any(c in filters for c in s.classes)]
    counts = {}
    for s in surfaces:
        for c in s.classes:
            if filters and c not in filters:
                continue
            counts[c] = counts.get(c, 0) + 1

    n_ok = sum(1 for p in result.pages if not p.error)
    n_err = sum(1 for p in result.pages if p.error)
    err_bit = ("{bred}" + str(n_err) + "{rst}") if n_err else "0"

    print()
    info("{bright}=== Web Recon Overview: {byellow}" + result.target + "{rst}{bright} ==={rst}")
    if from_cache:
        info("{byellow}Cache hit{rst} — reusing results (same crawl options). {bgreen}--force-rescan{rst} to crawl again.")
    if filters:
        info("Filter: {bmagenta}" + ", ".join(class_filters or []) + "{rst}")
    info(
        "Pages crawled: {byellow}"
        + str(len(result.pages))
        + "{rst}  ok={bgreen}"
        + str(n_ok)
        + "{rst}  errors="
        + err_bit
    )
    info("Input surfaces: {byellow}" + str(len(surfaces) if filters else len(result.surfaces)) + "{rst}")
    err_log = Path(result.output_dir) / "errors.log"
    dbg_log = Path(result.output_dir) / "debug.log"
    if n_err or result.errors:
        info("Error log: {bgreen}" + str(err_log) + "{rst}")
    if dbg_log.is_file():
        info("Debug log: {bgreen}" + str(dbg_log) + "{rst}")
    info("{bright}Candidate classes:{rst}")
    if counts:
        for cls, n in sorted(counts.items(), key=lambda kv: (_priority(kv[0]), kv[0])):
            info("  {bmagenta}" + cls + "{rst}: {byellow}" + str(n) + "{rst}")
    else:
        info("  (none)")
    sqli_s = [s for s in surfaces if "sqli" in s.classes]
    if (not filters or "sqli" in filters) and sqli_s:
        n_high = sum(1 for s in sqli_s if s.sqli_priority == "HIGH")
        n_med = sum(1 for s in sqli_s if s.sqli_priority == "MEDIUM")
        info(
            "SQLi candidate sinks: {byellow}"
            + str(n_high)
            + "{rst} HIGH / {byellow}"
            + str(n_med)
            + "{rst} MEDIUM (pastables only, not sent)"
        )
    info("{bright}Top candidate inputs:{rst}")
    ranked = [s for s in surfaces if s.classes]
    ranked.sort(
        key=lambda s: (
            _priority(next(c for c in s.classes if not filters or c in filters)),
            s.page_path,
            s.param,
        )
    )
    shown = 8
    for i, s in enumerate(ranked[:shown], 1):
        display = _display_path(s)
        labels = [c for c in s.classes if not filters or c in filters]
        info(
            "  "
            + str(i)
            + ". {bblue}"
            + s.method
            + "{rst} "
            + display
            + "  param={bgreen}"
            + s.param
            + "{rst}  [{bmagenta}"
            + ", ".join(labels)
            + "{rst}]"
        )
    if not ranked:
        info("  (none)")
    classified = Path(result.output_dir) / "classified.md"
    manual = Path(result.output_dir) / "manual_checks.md"
    info(
        "Full classified report saved to {bgreen}"
        + str(classified)
        + "{rst}. For additional manual checks and bypass variants, see {bgreen}"
        + manual.name
        + "{rst}."
    )
    info("{bright}Don't forget to check classified.md and manual_checks.md for commands to run manually.{rst}")
    print()


def print_class_pastables(result: ReconResult, class_filters: list[str], verbose: bool = False) -> None:
    """Dump matching pastables to the terminal (copy-pasteable, no [*] on payload lines)."""
    filters = set(class_filters)
    hits = [s for s in result.surfaces if any(c in filters for c in s.classes)]
    if not hits:
        info("No surfaces matched filter {bmagenta}" + ", ".join(class_filters) + "{rst}.")
        return
    info("{bright}=== Filtered pastables ({bmagenta}" + ", ".join(class_filters) + "{rst}{bright}) ==={rst}")
    print()
    for s in hits:
        display = _display_path(s)
        matching = [c for c in s.classes if c in filters]
        for cls in matching:
            extra = ""
            if cls == "sqli" and s.sqli_priority:
                extra = " [" + s.sqli_priority + "]"
            info(
                "{bblue}"
                + s.method
                + "{rst} "
                + display
                + "  param={bgreen}"
                + s.param
                + "{rst}  {bmagenta}"
                + cls
                + extra
                + "{rst}"
            )
            if s.why.get(cls):
                info("  " + s.why[cls])
            cmds = list(s.canonical.get(cls) or [])
            if verbose:
                cmds.extend(s.verbose.get(cls) or [])
            if cmds:
                print()
                print("\n".join(cmds))
                print()
            else:
                info("  (no pastable template)")
    print()
