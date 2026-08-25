"""Passive helpers: attacker IP guess (tun0), header formatting, robots/sitemap parse."""

from __future__ import annotations

import fcntl
import re
import socket
import struct
import xml.etree.ElementTree as ET
from pathlib import Path

from web_recon.models import RobotsInfo

SIOCGIFADDR = 0x8915
VPN_IFACES = ("tun0", "tap0", "wg0", "vpn0", "tun1")


def detect_attacker_ip() -> str | None:
    """Best-effort OSCP VPN IP. Never fails the run; returns None if unknown."""
    for iface in VPN_IFACES:
        ip = _iface_ipv4(iface)
        if ip and not ip.startswith("127."):
            return ip
    return None


def _iface_ipv4(iface: str) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = struct.pack("256s", iface.encode("utf-8")[:15])
            info = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, packed)
            return socket.inet_ntoa(info[20:24])
        finally:
            sock.close()
    except OSError:
        return None


def sanitize_filename(url: str, used: set[str]) -> str:
    from urllib.parse import urlparse
    import hashlib

    p = urlparse(url)
    path = (p.path or "/").strip("/") or "index"
    path = re.sub(r"[^A-Za-z0-9._-]+", "_", path)
    if p.query:
        digest = hashlib.sha1(p.query.encode("utf-8", errors="replace")).hexdigest()[:8]
        path = f"{path}__{digest}"
    if p.fragment:
        frag = re.sub(r"[^A-Za-z0-9._-]+", "_", p.fragment)[:40]
        if frag:
            path = f"{path}__h_{frag}"
    if not path.endswith(".html"):
        path += ".html"
    path = path[:180]
    candidate = path
    i = 2
    while candidate in used:
        stem = path[:-5] if path.endswith(".html") else path
        candidate = f"{stem}_{i}.html"
        i += 1
    used.add(candidate)
    return candidate


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def xml_localname(tag: str) -> str:
    return tag.split("}", 1)[-1] if tag else ""


def parse_robots(text: str, url: str, status: int | None = 200) -> RobotsInfo:
    info = RobotsInfo(url=url, fetched=True, status=status, raw=text or "")
    current_ua: list[str] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            info.other.append(line)
            continue
        key, _, val = line.partition(":")
        key_l = key.strip().lower()
        val = val.strip()
        if key_l == "user-agent":
            current_ua.append(val)
            info.user_agents.append(val)
        elif key_l == "disallow":
            info.disallow.append(val)
        elif key_l == "allow":
            info.allow.append(val)
        elif key_l == "sitemap":
            info.sitemaps.append(val)
        else:
            info.other.append(f"{key}: {val}")
    return info


def parse_sitemap_locs(xml_text: str) -> tuple[list[str], list[str]]:
    """Return (page_or_url_locs, nested_sitemap_locs)."""
    urls: list[str] = []
    nested: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Fallback: naive <loc> scrape
        for m in re.findall(r"<loc>\s*([^<]+)\s*</loc>", xml_text or "", flags=re.I):
            urls.append(m.strip())
        return urls, nested

    root_name = xml_localname(root.tag).lower()
    for el in root.iter():
        name = xml_localname(el.tag).lower()
        if name != "loc" or el.text is None:
            continue
        loc = el.text.strip()
        if not loc:
            continue
        if root_name == "sitemapindex":
            nested.append(loc)
        else:
            urls.append(loc)
    if root_name == "sitemapindex" and not nested and urls:
        nested, urls = urls, []
    return urls, nested
