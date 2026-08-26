"""Passive helpers: attacker IP guess, header formatting, robots/sitemap parse."""

from __future__ import annotations

import fcntl
import ipaddress
import re
import socket
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from web_recon.models import RobotsInfo

SIOCGIFADDR = 0x8915
VPN_IFACES = ("tun0", "tap0", "wg0", "vpn0", "tun1")


def detect_attacker_ip(target: str | None = None) -> str | None:
    """Local IPv4/IPv6 the OS would use to reach *target*, else a VPN iface.

    Hostname URLs (``http://hostname.local``) are resolved the same way the
    kernel would for a connect — mDNS/DNS plus the routing table. Loopback is
    never used as ``<ATTACKER_IP>``. Returns None if nothing usable is found.
    """
    host, port = host_port_from_target(target)
    if host:
        ip = source_ip_toward(host, port)
        if ip:
            return ip
    for iface in VPN_IFACES:
        ip = _iface_ipv4(iface)
        if ip and _usable_attacker_ip(ip):
            return ip
    return None


def host_port_from_target(target: str | None) -> tuple[str | None, int]:
    if not target or not str(target).strip():
        return None, 80
    raw = str(target).strip()
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        return None, 80
    scheme = (parsed.scheme or "http").lower()
    default = 443 if scheme == "https" else 80
    return host, parsed.port or default


def source_ip_toward(host: str, port: int) -> str | None:
    """UDP connect (no packet needed) so getsockname() shows the chosen source IP."""
    dest_port = port or 80
    for family in (socket.AF_INET, socket.AF_INET6):
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.connect((host, dest_port))
            ip = _normalize_ip(sock.getsockname()[0])
            if _usable_attacker_ip(ip):
                return ip
        except OSError:
            continue
        finally:
            if sock is not None:
                sock.close()
    return None


def _normalize_ip(ip: str) -> str:
    if not ip:
        return ip
    core = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(core)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def _usable_attacker_ip(ip: str) -> bool:
    if not ip:
        return False
    core = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(core)
    except ValueError:
        return False
    return not addr.is_loopback and not addr.is_unspecified


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


def parse_allow_methods(*values: str) -> list[str]:
    """Parse Allow / Access-Control-Allow-Methods into unique uppercase verbs."""
    seen: set[str] = set()
    out: list[str] = []
    for val in values:
        for part in (val or "").replace(";", ",").split(","):
            method = part.strip().upper()
            if not method or method in seen:
                continue
            seen.add(method)
            out.append(method)
    return out
