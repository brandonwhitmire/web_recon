"""Map inventoried surfaces to candidate classes and fill operator pastables.

Pure output: never executes commands or sends payloads.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from web_recon_heuristics import (
    CONTEXT_TRIGGERS,
    PARAM_NAME_TRIGGERS,
    PASTABLES,
    classify_input,
    pastables_for,
)

from web_recon.extract import flags_for_query_param
from web_recon.models import PageRecord, Surface
from web_recon.scope import page_path_of

REFLECTION_CLASSES = {"xss", "ssti", "xxe"}
REFLECTION_NOTE = (
    "Manually confirm this reflects in the response (Page Source vs Inspect Element). "
    "This tool does not probe reflection."
)

CLASS_PRIORITY = [
    "file_inclusion",
    "command_injection",
    "file_upload",
    "ssrf",
    "ssti",
    "xxe",
    "xss",
    "idor",
    "verb_tampering",
]


def fill_placeholders(text: str, mapping: dict[str, str]) -> str:
    """Replace <PLACEHOLDER> tokens. Unknown keys stay as literal placeholders.

    `http://<TARGET>` is replaced with the real origin first so HTTPS labs don't
    emit the wrong scheme.
    """
    out = text
    origin = mapping.get("ORIGIN")
    target = mapping.get("TARGET")
    if origin:
        out = out.replace("http://<TARGET>", origin)
        out = out.replace("https://<TARGET>", origin)
    if target:
        out = out.replace("<TARGET>", target)
    for key, value in mapping.items():
        if key in {"ORIGIN", "TARGET"} or value is None:
            continue
        out = out.replace(f"<{key}>", str(value))
    return out


def mapping_for(
    *,
    origin: str,
    page_url: str,
    param: str,
    attacker_ip: str | None,
    php_file: str | None,
) -> dict[str, str]:
    parsed = urlparse(origin)
    host = parsed.hostname or ""
    port = parsed.port
    if port and not ((parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)):
        target = f"{host}:{port}"
    else:
        target = host
    page = page_path_of(page_url)
    m = {
        "ORIGIN": origin.rstrip("/"),
        "TARGET": target,
        "PAGE": page,
        "PARAM": param if param not in {"", "*"} else "<PARAM>",
    }
    if attacker_ip:
        m["ATTACKER_IP"] = attacker_ip
    if php_file:
        m["FILE"] = php_file
    return m


def why_for(class_key: str, param_name: str | None, flags: set[str]) -> str:
    entry = PASTABLES.get(class_key) or {}
    base = entry.get("why", class_key)
    details: list[str] = []
    if param_name:
        needles = PARAM_NAME_TRIGGERS.get(class_key, [])
        hits = [n for n in needles if n in param_name.lower()]
        if hits:
            details.append(f"param '{param_name}' matched {hits}")
    ctx_needles = CONTEXT_TRIGGERS.get(class_key, [])
    ctx_hits = [f for f in ctx_needles if f in flags]
    if ctx_hits:
        details.append("context " + ", ".join(ctx_hits))
    if details:
        return f"{base} ({'; '.join(details)})"
    return base


def _priority(cls: str) -> int:
    try:
        return CLASS_PRIORITY.index(cls)
    except ValueError:
        return len(CLASS_PRIORITY)


def emit_surface(
    surface: Surface,
    *,
    origin: str,
    attacker_ip: str | None,
    php_file: str | None,
) -> Surface:
    flags = set(surface.context_flags)
    classes = classify_input(surface.param if surface.param != "*" else None, flags)
    # Site-wide OPTIONS / verb tampering
    if surface.kind == "site" and "any_endpoint" in flags:
        if "verb_tampering" not in classes:
            classes.append("verb_tampering")
    mapping = mapping_for(
        origin=origin,
        page_url=surface.page_url,
        param=surface.param,
        attacker_ip=attacker_ip,
        php_file=php_file,
    )
    surface.classes = classes
    for cls in classes:
        packed = pastables_for(cls, verbose=False)
        packed_v = pastables_for(cls, verbose=True)
        if not packed:
            continue
        surface.why[cls] = why_for(cls, surface.param, flags)
        note = packed.get("note") or ""
        if cls in REFLECTION_CLASSES:
            note = (REFLECTION_NOTE + " " + note).strip()
            surface.reflection_classes.append(cls)
        if surface.method and surface.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            note = f"Surface method is {surface.method.upper()}; adapt the GET pastable (Burp / curl -X {surface.method.upper()} -d). " + note
        surface.notes[cls] = note
        surface.canonical[cls] = [fill_placeholders(c, mapping) for c in packed.get("commands", [])]
        extra = []
        if packed_v:
            extra = packed_v.get("commands", [])[len(packed.get("commands", [])) :]
        surface.verbose[cls] = [fill_placeholders(c, mapping) for c in extra]
    return surface


def _surface_id(kind: str, method: str, path: str, param: str, seq: int) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", f"{kind}-{method}-{path}-{param}").strip("-").lower()
    slug = slug[:80] or "surface"
    return f"{slug}-{seq}"


KIND_RANK = {"form_field": 3, "query_param": 2, "js_param": 1, "site": 0}


def _merge_or_add(bucket: dict[tuple[str, str, str], Surface], s: Surface) -> None:
    key = (s.page_path, s.param.lower(), s.method.upper())
    existing = bucket.get(key)
    if not existing:
        bucket[key] = s
        return
    if KIND_RANK.get(s.kind, 0) > KIND_RANK.get(existing.kind, 0):
        existing.kind = s.kind
        existing.field_type = s.field_type or existing.field_type
        existing.page_url = s.page_url or existing.page_url
    existing.context_flags = sorted(set(existing.context_flags) | set(s.context_flags))
    if s.sample_value and not existing.sample_value:
        existing.sample_value = s.sample_value
    if s.evidence and s.evidence not in existing.evidence:
        existing.evidence = (existing.evidence + "; " + s.evidence).strip("; ")


def build_surfaces(pages: list[PageRecord]) -> list[Surface]:
    bucket: dict[tuple[str, str, str], Surface] = {}
    seq = 0

    def add(**kwargs) -> None:
        nonlocal seq
        seq += 1
        s = Surface(id=_surface_id(kwargs.get("kind", "x"), kwargs.get("method", "GET"), kwargs.get("page_path", ""), kwargs.get("param", ""), seq), **kwargs)
        _merge_or_add(bucket, s)

    for page in pages:
        if page.error and not page.forms and not page.query_params:
            continue
        page_url = page.final_url or page.url
        path = page_path_of(page_url)

        for name, value in page.query_params:
            add(
                kind="query_param",
                page_url=page_url,
                page_path=path,
                method="GET",
                param=name,
                sample_value=value,
                field_type="query",
                context_flags=list(flags_for_query_param(name, value)),
                evidence=f"URL query on {path or '/'}",
            )

        for form in page.forms:
            form_path = page_path_of(form.action) if form.action else path
            form_url = form.action or page_url
            for field in form.fields:
                add(
                    kind="form_field",
                    page_url=form_url,
                    page_path=form_path,
                    method=form.method or "GET",
                    param=field.name,
                    sample_value=field.value,
                    field_type=field.field_type,
                    context_flags=list(field.flags),
                    evidence=f"{form.method} form {form_path or '/'} enctype={form.enctype}",
                )

        for field in page.loose_fields:
            add(
                kind="form_field",
                page_url=page_url,
                page_path=path,
                method="GET",
                param=field.name,
                sample_value=field.value,
                field_type=field.field_type,
                context_flags=list(field.flags),
                evidence=f"DOM control on {path or '/'} (no enclosing form)",
            )

        for ep in page.js_endpoints:
            q = urlparse(ep).query
            if q:
                for name, value in parse_qsl(q, keep_blank_values=True):
                    add(
                        kind="js_param",
                        page_url=ep,
                        page_path=page_path_of(ep),
                        method="GET",
                        param=name,
                        sample_value=value,
                        field_type="js",
                        context_flags=list(flags_for_query_param(name, value)),
                        evidence=f"JS-referenced endpoint {ep}",
                    )

    # Always emit one site-level verb-tampering candidate (heuristics `any_endpoint`).
    first_url = pages[0].final_url if pages else "/"
    add(
        kind="site",
        page_url=first_url,
        page_path="",
        method="OPTIONS",
        param="*",
        field_type="endpoint",
        context_flags=["any_endpoint"],
        evidence="site-wide: every endpoint may honor alternate HTTP verbs",
    )
    return list(bucket.values())


def classify_all(
    pages: list[PageRecord],
    *,
    origin: str,
    attacker_ip: str | None,
    php_files: list[str],
) -> list[Surface]:
    php_file = php_files[0] if php_files else None
    surfaces = build_surfaces(pages)
    out = [
        emit_surface(s, origin=origin, attacker_ip=attacker_ip, php_file=php_file)
        for s in surfaces
    ]
    out.sort(key=lambda s: (_best_priority(s.classes), s.page_path, s.param))
    return out


def _best_priority(classes: list[str]) -> int:
    if not classes:
        return 99
    return min(_priority(c) for c in classes)


def count_classes(surfaces: list[Surface]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for s in surfaces:
        for c in s.classes:
            counts[c] = counts.get(c, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (_priority(kv[0]), kv[0])))
