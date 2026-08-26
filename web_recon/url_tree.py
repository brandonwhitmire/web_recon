"""ASCII URL trees (tree(1)-style) for Phase 2 crawl output."""

from __future__ import annotations

from urllib.parse import urlparse

MID = "├── "
END = "└── "
PIPE = "│   "
PAD = "    "


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


def format_url_tree(urls: list[str], root: str) -> str:
    """Full nested tree with correct └── on last siblings. Insertion order."""
    children: dict[str, dict] = {}
    seen: set[str] = set()
    for url in urls:
        key = url.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        node = children
        for seg in url_segments(key):
            node = node.setdefault(seg, {})
    lines = [root]
    lines.extend(_render_children(children, prefix=""))
    return "\n".join(lines)


def _render_children(children: dict[str, dict], prefix: str) -> list[str]:
    items = list(children.items())
    lines: list[str] = []
    for i, (name, child) in enumerate(items):
        last = i == len(items) - 1
        branch = END if last else MID
        lines.append(prefix + branch + name)
        ext = PAD if last else PIPE
        lines.extend(_render_children(child, prefix + ext))
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
