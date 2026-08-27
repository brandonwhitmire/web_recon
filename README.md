# web_recon

**NOTE:** 100% vibe-coded with AI... use at your own risk

Passive web recon for authorized labs (OSCP prep). Renders the target, crawls same-host pages, inventories inputs, tags **candidate** vuln classes, and prints pastables. GET navigation plus one OPTIONS on the start URL. Never submits forms, sends payloads, or runs scanners.

## Setup

Python 3.10+. After install, Chromium is still required (`playwright` does not bundle browsers in the wheel).

### Python Wheel from Github

```bash
pip install --break-system-packages --upgrade playwright
python3 -m playwright install chromium
python3 -m playwright install-deps chromium
pipx ensurepath
pipx install git+https://github.com/brandonwhitmire/web_recon.git
```

That installs whatever is currently on `main` (no version pin). Re-run with `--upgrade` to pick up later commits.

### Local clone

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
playwright install chromium
```

Editable (development): `pip install -e .`

## Usage

```bash
web_recon http://10.10.11.12
web_recon http://target.web --verbose --attacker-ip 10.10.14.8
web_recon https://app.lab -o /tmp --max-pages 40
web_recon --help
```

`python -m web_recon` is the same command.

`--attacker-ip` fills `<ATTACKER_IP>` in pastables. If omitted, the local address the OS would use to reach the target hostname (DNS/mDNS + routing) is used, then `tun0` if that cannot be determined.

`--verbose` adds bypass ladders to `classified.md` and Phase 3 terminal output (they always land in `manual_checks.md`).

`--debug` writes extra crawl/request detail to `debug.log`. Page, robots.txt, sitemap, and OPTIONS failures always go to `errors.log`.

### Cache and filters

A crawl is reused when the target and crawl options match (flag order does not matter). Classifier flags only filter what gets printed.

```bash
web_recon http://10.10.11.12
web_recon http://10.10.11.12 --sqli
web_recon http://10.10.11.12 --xss --ssti
web_recon http://10.10.11.12 --lfi
web_recon http://10.10.11.12 --force-rescan
```

Filters: `--sqli` `--xss` `--ssti` `--ssrf` `--xxe` `--lfi` / `--file-inclusion` `--cmdi` / `--command-injection` `--file-upload` `--idor` `--verb-tampering`.

## Output

Default `--output` is `~`. Files land next to AutoRecon's other target dirs:

```
~/results/<target>/web_scan/
  summary.md          headers, OPTIONS, robots.txt, sitemap, tech fingerprint
  crawl_map.md        URLs, forms, params, comments
  classified.md       candidate classes (high → low) → pastables
  manual_checks.md    extra / verbose pastables
  inventory.json
  errors.log          page / robots / sitemap failures
  debug.log           only with --debug
  dom/                rendered DOM per page
```

`--output /tmp` writes to `/tmp/results/<target>/web_scan/` instead.

## Tests

From a local clone (`pip install -e .`):

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
```

E2E needs Chromium (`playwright install chromium`); it skips if Chromium is missing. Unit tests only:

```bash
python -m unittest tests.test_classify tests.test_extract tests.test_fingerprint tests.test_guardrails tests.test_scope tests.test_util tests.test_url_tree tests.test_runlog tests.test_phase_output -v
```
