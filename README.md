# web-recon

Passive web recon for authorized labs (OSCP prep). Renders the target, crawls same-host pages, inventories inputs, tags **candidate** vuln classes, and prints pastables. GET-only. Never submits forms, sends payloads, or runs scanners.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

Python 3.10+.

## Usage

```bash
python -m web_recon http://10.10.11.12
python -m web_recon http://target.web --verbose --attacker-ip 10.10.14.8
python -m web_recon https://app.lab -o ./results --max-pages 40
python -m web_recon --help
```

`--attacker-ip` fills `<ATTACKER_IP>` in pastables. If omitted, `tun0` is used when present.

`--verbose` adds bypass ladders to `classified.md` (they always land in `manual_checks.md`).

## Output

```
results/<target>/
  summary.md          headers, robots.txt, sitemap, tech fingerprint
  crawl_map.md        URLs, forms, params, comments
  classified.md       input → candidate class → pastables
  manual_checks.md    extra / verbose pastables
  inventory.json
  dom/                rendered DOM per page
```

## Tests

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
```

E2E needs Chromium (`playwright install chromium`); it skips if Chromium is missing. Unit tests only:

```bash
python -m unittest tests.test_classify tests.test_extract tests.test_fingerprint tests.test_guardrails tests.test_scope -v
```
