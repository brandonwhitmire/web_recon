"""ASCII URL trees (tree(1)-style) for Phase 2 crawl output.

Field groups hang off the page URL they were parsed from, so the diagram shows
where each input sits in the crawled DOM.
"""

from __future__ import annotations

from urllib.parse import urlparse

from web_recon.models import FormRecord, PageRecord

MID = "├── "
END = "└── "
PIPE = "│   "
PAD = "    "

# Buttons are not attack inputs; everything else (including hidden) is shown.
_SKIP_FIELD_TYPES = {"submit", "button", "reset", "image"}


def url_segments(url: str) -> list[str]:
    """Split a URL into tree nodes: path segments, then ?query if present."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    segs = [s for s in path.split("/") if s]
    parts = ["/"] if not segs else segs
    if parsed.query:
        parts.append("?" + parsed.query)
    return parts


class _Node:
    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        self.groups: list[tuple[str, list[str]]] = []


def _field_line(name: str, field_type: str) -> str:
    label = (name or "").strip() or "(unnamed)"
    kind = (field_type or "text").strip() or "text"
    return f"{label}  {kind}"


def _keep_field(field_type: str) -> bool:
    return (field_type or "").strip().lower() not in _SKIP_FIELD_TYPES


def _form_label(form: FormRecord) -> str:
    method = (form.method or "GET").upper()
    path = urlparse(form.action or "").path or "/"
    if not path.startswith("/"):
        path = "/" + path
    label = f"{method} {path}"
    if form.has_file_input:
        label += "  multipart"
    return label


def field_groups(page: PageRecord) -> list[tuple[str, list[str]]]:
    """(group label, field lines) for inputs parsed from this page."""
    groups: list[tuple[str, list[str]]] = []
    query = [_field_line(name, "query") for name, _value in (page.query_params or []) if (name or "").strip()]
    if query:
        groups.append(("query", query))
    for form in page.forms or []:
        lines = [
            _field_line(field.name, field.field_type)
            for field in form.fields
            if _keep_field(field.field_type)
        ]
        if lines:
            groups.append((_form_label(form), lines))
    loose = [
        _field_line(field.name, field.field_type)
        for field in (page.loose_fields or [])
        if _keep_field(field.field_type)
    ]
    if loose:
        groups.append(("loose", loose))
    return groups


def format_url_tree(urls: list[str], root: str) -> str:
    """Full nested tree with correct └── on last siblings. Insertion order."""
    return format_page_tree([_url_only(u) for u in urls], root)


def format_page_tree(pages: list[PageRecord], root: str) -> str:
    """URL tree plus the inputs parsed from each page."""
    root_node = _Node()
    seen: set[str] = set()
    for page in pages:
        url = (page.final_url or page.url or "").strip()
        if not url:
            continue
        node = root_node
        for seg in url_segments(url):
            node = node.children.setdefault(seg, _Node())
        groups = field_groups(page)
        if url not in seen:
            seen.add(url)
        node.groups.extend(groups)
    lines = [root]
    lines.extend(_render_node(root_node, ""))
    return "\n".join(lines)


def _url_only(url: str) -> PageRecord:
    return PageRecord(url=url, final_url=url, status=None)


def _render_node(node: _Node, prefix: str) -> list[str]:
    url_items = list(node.children.items())
    groups = [(title, fields) for title, fields in node.groups if fields]
    total = len(url_items) + len(groups)
    lines: list[str] = []
    idx = 0
    for name, child in url_items:
        idx += 1
        last = idx == total
        branch = END if last else MID
        lines.append(prefix + branch + name)
        ext = PAD if last else PIPE
        lines.extend(_render_node(child, prefix + ext))
    for title, fields in groups:
        idx += 1
        last = idx == total
        branch = END if last else MID
        lines.append(prefix + branch + title)
        ext = PAD if last else PIPE
        for j, field in enumerate(fields):
            fb = END if j == len(fields) - 1 else MID
            lines.append(prefix + ext + fb + field)
    return lines


class LiveUrlTree:
    """Print the root once, then only new nodes as URLs are visited (always ├──)."""

    def __init__(self, host: str) -> None:
        self.host = host
        self.urls: list[str] = []
        self._printed: set[tuple[str, ...]] = set()
        self._started = False

    def header_line(self) -> str:
        return "{bright}[{yellow}" + self.host + "{crst}/{bgreen}crawl{crst}]{rst}"

    def start_lines(self) -> list[str]:
        self._started = True
        return [self.host]

    def add(self, url: str) -> list[str]:
        key = (url or "").strip()
        if not key:
            return []
        self.urls.append(key)
        new: list[str] = []
        path: list[str] = []
        for seg in url_segments(key):
            path.append(seg)
            t = tuple(path)
            if t in self._printed:
                continue
            self._printed.add(t)
            depth = len(t)
            new.append((PIPE * (depth - 1)) + MID + seg)
        return new

    def add_fields(self, page: PageRecord) -> list[str]:
        """Ensure the page URL is in the tree, then print its parsed inputs."""
        url = (page.final_url or page.url or "").strip()
        lines = self.add(url) if url else []
        if not url:
            return lines
        depth = len(url_segments(url))
        segs = url_segments(url)
        for i, (title, fields) in enumerate(field_groups(page)):
            if not fields:
                continue
            gkey = tuple(segs + [f"@{i}:{title}"])
            if gkey not in self._printed:
                self._printed.add(gkey)
                lines.append((PIPE * depth) + MID + title)
            for field in fields:
                fkey = gkey + (field,)
                if fkey in self._printed:
                    continue
                self._printed.add(fkey)
                lines.append((PIPE * (depth + 1)) + MID + field)
        return lines
