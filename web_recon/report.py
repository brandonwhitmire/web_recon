"""AutoRecon-style report writers. Markdown + JSON + console overview."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from web_recon.classify import _priority
from web_recon.models import Fingerprint, Header, ReconResult, Surface
from web_recon.term import info

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


def _surface_md(lines: list[str], s: Surface, include_verbose: bool) -> None:
    path = s.page_path or "/"
    display = path if path.startswith("/") else ("/" + path if path != "/" else "/")
    if path == "":
        display = "/"
    elif not path.startswith("/"):
        display = "/" + path
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
        path = s.page_path or "/"
        display = path if str(path).startswith("/") else ("/" + path if path else "/")
        if path == "":
            display = "/"
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


def print_overview(result: ReconResult) -> None:
    n_ok = sum(1 for p in result.pages if not p.error)
    n_err = sum(1 for p in result.pages if p.error)
    err_bit = ("{bred}" + str(n_err) + "{rst}") if n_err else "0"

    print()
    info("{bright}=== Web Recon Overview: {byellow}" + result.target + "{rst}{bright} ==={rst}")
    info(
        "Pages crawled: {byellow}"
        + str(len(result.pages))
        + "{rst}  ok={bgreen}"
        + str(n_ok)
        + "{rst}  errors="
        + err_bit
    )
    info("Input surfaces: {byellow}" + str(len(result.surfaces)) + "{rst}")
    info("{bright}Candidate classes:{rst}")
    if result.class_counts:
        for cls, n in result.class_counts.items():
            info("  {bmagenta}" + cls + "{rst}: {byellow}" + str(n) + "{rst}")
    else:
        info("  (none)")
    info("{bright}Top candidate inputs:{rst}")
    ranked = [s for s in result.surfaces if s.classes]
    ranked.sort(key=lambda s: (_priority(s.classes[0]) if s.classes else 99, s.page_path, s.param))
    for i, s in enumerate(ranked[:8], 1):
        path = s.page_path or "/"
        display = "/" + path if path and not path.startswith("/") else (path or "/")
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
            + ", ".join(s.classes)
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
