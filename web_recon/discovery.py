"""Filled operator pastables for recon that this tool does not run.

vHost brute-force, a deeper crawl, directory brute-force, and (when the
fingerprint looks like WordPress) WPScan. Printed only — never executed.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from web_recon.classify import fill_placeholders
from web_recon.models import ReconResult
from web_recon.util import resolve_host_ip

LIN_EXTENSIONS = "php,html,htm,txt,bak,zip,xml,json,js,sh,py,config"
WIN_EXTENSIONS = "asp,aspx,ashx,asmx,html,htm,txt,bak,zip,xml,json,js,config,cs"

_WIN_HINTS = ("iis", "asp.net", "aspx", "windows", "microsoft-iis")
_WP_URL_RE = re.compile(r"wp-content|wp-includes|wp-login|xmlrpc\.php|/wp-json|wp-admin", re.I)
_WP_PATHS = (
    "/wp-admin",
    "/wp-login.php",
    "/wp-content",
    "/xmlrpc.php",
    "/readme.txt",
    "/feed",
    "/wp-json",
)

VHOST_TEMPLATE = """\
Only changes the HTTP Host header. Use the target scheme (http vs https).

# NOTE: filter out by response size since an HTTP response of 200 OK will always be received
ffuf -ic -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -H 'Host: FUZZ.<DOMAIN>' -u http://<TARGET>/ -fs <SIZE>

ffuf -ic -w /usr/share/seclists/Discovery/DNS/services-names.txt:FUZZ -H 'Host: FUZZ.<DOMAIN>' -u http://<TARGET>/ -fs <SIZE>

# Add NEW vHosts to automatically resolve them later
echo '<IP_ADDR> <VHOST>.<FQDN>' | sudo tee -a /etc/hosts
"""

CRAWL_TEMPLATE = """\
https://github.com/projectdiscovery/katana

sudo apt install -y golang
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

$HOME/go/bin/katana -output katana_crawl.txt -depth 5 -u http://<TARGET>
"""

DIR_TEMPLATE = """\
Larger directory list:
    /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
Older websites:
    /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt

Scheme follows the target. feroxbuster sometimes mishandles https and DNS; --insecure is included.

# Directory Bruteforce
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 5 -o feroxbuster_dir_common --scan-dir-listings --insecure --redirects -u http://<TARGET>

# Bruteforce w/ File Extensions (<EXT_NOTE>)
# LIN:  -x php,html,htm,txt,bak,zip,xml,json,js,sh,py,config
# WIN:  -x asp,aspx,ashx,asmx,html,htm,txt,bak,zip,xml,json,js,config,cs
feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 5 -o feroxbuster_dir_extensions --scan-dir-listings --insecure --redirects -u http://<TARGET> -x <EXTENSIONS>
"""

WORDPRESS_TEMPLATE = """\
WPScan: https://github.com/wpscanteam/wpscan
    API for Vuln DB (free use requires token): https://wpscan.com/api/
    API Token: https://wpscan.com/profile/

WPScan is useful, and manual enumeration sometimes finds more (plugins the scanner misses).

/robots.txt
/wp-admin
/wp-content/plugins
/wp-content/themes
/wp-login.php
/readme.txt

Users: Administrator (code edit → RCE), Editor, Author, Contributor, Subscriber.

# Basic
curl -so- 'http://<TARGET>/robots.txt'
curl -s http://<TARGET> | grep -i -e WordPress -e themes -e plugins

# Version
curl -s http://<TARGET>/readme.txt | grep -i version
curl -s http://<TARGET>/feed/ | grep -i generator
curl -s http://<TARGET> | grep -i 'meta name="generator"'

# Users via API
curl -s http://<TARGET>/wp-json/wp/v2/users | python3 -m json.tool

# Basic Enumerate
sudo wpscan -t 50 --enumerate u,vp,vt,tt,cb,dbe --plugins-detection passive --api-token <API_TOKEN> --url http://<TARGET>

# Aggressive Plugins
sudo wpscan -t 50 --enumerate p --plugins-detection aggressive --api-token <API_TOKEN> --url http://<TARGET>

# Login brute-force: xmlrpc and wp-login methods
sudo wpscan -t 20 --url http://<TARGET> --password-attack xmlrpc -U <USER> -P /usr/share/wordlists/rockyou.txt
sudo wpscan -t 20 --url http://<TARGET> --password-attack wp-login -U <USER> -P /usr/share/wordlists/rockyou.txt
"""


def _host_of(result: ReconResult) -> str:
    parsed = urlparse(result.origin or result.start_url or "")
    return (parsed.hostname or "").lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def uses_windows_stack(result: ReconResult) -> bool:
    fp = result.fingerprint
    blob = " ".join(
        [fp.server or "", fp.powered_by or ""]
        + list(fp.os_hints or [])
        + [h.name or "" for h in fp.hits]
    ).lower()
    if any(hint in blob for hint in _WIN_HINTS):
        return True
    for page in result.pages:
        path = urlparse(page.final_url or page.url or "").path.lower()
        if path.endswith((".aspx", ".asp", ".ashx", ".asmx")):
            return True
        for form in page.forms or []:
            action = urlparse(form.action or "").path.lower()
            if action.endswith((".aspx", ".asp", ".ashx", ".asmx")):
                return True
    return False


def is_wordpress(result: ReconResult) -> bool:
    for hit in result.fingerprint.hits:
        if "wordpress" in (hit.name or "").lower():
            return True
    for page in result.pages:
        blob = " ".join([page.final_url or "", page.url or "", page.title or ""] + list(page.links or []))
        if _WP_URL_RE.search(blob):
            return True
    robots = result.robots
    if robots:
        raw = " ".join(robots.disallow or []) + " " + (robots.raw or "")
        if _WP_URL_RE.search(raw):
            return True
    return False


def wordpress_notes(result: ReconResult) -> list[str]:
    """What the crawl already saw. Not a second scan."""
    notes: list[str] = []
    for hit in result.fingerprint.hits:
        if "wordpress" not in (hit.name or "").lower():
            continue
        ver = f" {hit.version}" if hit.version else ""
        src = f" [{hit.source}]" if hit.source else ""
        notes.append(f"fingerprint: {hit.name}{ver}{src}")
    urls: list[str] = []
    for page in result.pages:
        urls.append(page.final_url or page.url or "")
        urls.extend(page.links or [])
    blob = "\n".join(urls).lower()
    seen = [path for path in _WP_PATHS if path in blob]
    robots = result.robots
    if robots:
        for rule in robots.disallow or []:
            if "wp-" in rule.lower() or "wordpress" in rule.lower():
                seen.append("robots Disallow: " + rule)
    if seen:
        notes.append("seen: " + ", ".join(seen))
    return notes


def discovery_mapping(result: ReconResult, resolved_ip: str | None = None) -> dict[str, str]:
    origin = (result.origin or result.start_url or "").rstrip("/")
    parsed = urlparse(origin if "://" in origin else "http://" + origin)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "http").lower()
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        target = f"{host}:{port}"
    else:
        target = host
    windows = uses_windows_stack(result)
    mapping: dict[str, str] = {
        "ORIGIN": origin,
        "TARGET": target,
        "EXTENSIONS": WIN_EXTENSIONS if windows else LIN_EXTENSIONS,
        "EXT_NOTE": "windows/IIS/ASP.NET" if windows else "linux/PHP",
    }
    if host and _is_ip(host):
        mapping["IP_ADDR"] = host
    else:
        if host:
            mapping["DOMAIN"] = host
            mapping["FQDN"] = host
        if resolved_ip:
            mapping["IP_ADDR"] = resolved_ip
    return mapping


def _fill(template: str, mapping: dict[str, str]) -> str:
    return fill_placeholders(template, mapping).rstrip()


def discovery_sections(
    result: ReconResult,
    *,
    resolved_ip: str | None = None,
    resolve: bool = True,
) -> list[tuple[str, str]]:
    """(title, filled body) blocks to print. WordPress only when it was detected."""
    if resolved_ip is None and resolve:
        resolved_ip = resolve_host_ip(_host_of(result))
    mapping = discovery_mapping(result, resolved_ip)
    sections = [
        ("vHost Brute-Force", _fill(VHOST_TEMPLATE, mapping)),
        ("Crawling", _fill(CRAWL_TEMPLATE, mapping)),
        ("Directory Brute-Forcing", _fill(DIR_TEMPLATE, mapping)),
    ]
    if is_wordpress(result):
        body = _fill(WORDPRESS_TEMPLATE, mapping)
        notes = wordpress_notes(result)
        if notes:
            body = "# " + "\n# ".join(notes) + "\n\n" + body
        sections.append(("WordPress", body))
    return sections
