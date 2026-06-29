# NetScope — Complete Professional Audit Report

**Auditor:** Claude (Anthropic)  
**Audit Date:** 2026-06-27  
**Repo:** https://github.com/Ayaan-22/NetScope/tree/main  
**Version Audited:** v2.0.0 (as-committed)  
**Tests Run:** 96 passed, 0 failed  

---

## Executive Summary

NetScope is a well-structured async Python network scanner with a solid foundation. The Phase 1 and Phase 2 bug fixes are genuine and correctly implemented. The codebase is readable and mostly follows good practices. However, there are **significant gaps between README claims and reality**, multiple security risks, architectural dead ends, and a long list of missing features that make the tool incomplete as a "production-ready, portfolio-level" scanner. This report catalogs every finding with severity ratings and actionable upgrade guidance.

---

## Severity Key

| Rating | Meaning |
|--------|---------|
| 🔴 CRITICAL | Broken functionality, false claims, or security risk |
| 🟠 HIGH | Significant gap, missing feature, or design flaw |
| 🟡 MEDIUM | Quality issue, incomplete implementation, or UX problem |
| 🟢 LOW | Minor improvement, style, or nice-to-have |

---

## Section 1 — False/Misleading README Claims

These are actively inaccurate statements in the README that misrepresent the tool's actual state.

### 🔴 CRITICAL-1 — Coverage Claim is Wrong

**README says:** "~94% Coverage"  
**Reality:** Running `pytest --cov=src` produces **69% overall**:

```
src/scanner/engine.py       419 stmts,  142 missed  → 66%
src/utils/log_config.py      32 stmts,   32 missed  →  0%  ← NEVER TESTED
src/utils/config.py          68 stmts,    6 missed  → 91%
src/reporting/reporter.py    70 stmts,    2 missed  → 97%
TOTAL                       589 stmts,  182 missed  → 69%
```

`log_config.py` has **0% coverage**. The `_try_nmap_scan`, `_try_nmap_discovery`, `run_discovery`, `_ping_host`, `_nudge_host`, and `_read_arp_cache_*` functions in `engine.py` are entirely untested (lines 325–991). The 94% figure is fabricated or measured against a much earlier, smaller codebase.

**Fix:** Either write tests to actually reach 94%, or correct the README to state "~69% coverage."

---

### 🔴 CRITICAL-2 — Config Precedence is Wired Up But Not Applied

**README says:** "CLI arguments take precedence" over env → YAML → defaults.  
**Reality:** `main.py` calls `ScanConfig.load(args.config)` but **discards the result** (`_ = ScanConfig.load(...)`). The YAML/env values are loaded and immediately thrown away. The scanner is always instantiated with raw `argparse.Namespace` values — meaning YAML and env-var settings (except those coincidentally matching CLI defaults) are completely ignored at runtime.

```python
# main.py line ~140
_ = ScanConfig.load(args.config)   # ← result discarded, dead code

with NetScopeScanner(
    target=args.target,            # ← always from CLI args
    timeout=args.timeout,          # ← always from CLI args (default 1.5)
    ...
```

The entire `ScanConfig.load()` pipeline — including the carefully fixed DESIGN-3 precedence — is effectively dead code. Setting `NETSCOPE_TIMEOUT=5` in your shell has zero effect on the scan.

**Fix:** Merge `ScanConfig` values with `argparse` values, letting CLI args override YAML/env where explicitly set.

---

### 🟠 HIGH-3 — README Documents YAML Key `batch_size` but Code Uses `host_batch_size`

**README config example:**
```yaml
batch_size: 20
```
**settings.yaml.example uses:**
```yaml
host_batch_size: 20
```
**ScanConfig field name:**
```python
host_batch_size: int = 20
```
The YAML key documented in the README (`batch_size`) does not match the actual field (`host_batch_size`). A user copying the README example would silently get no effect.

---

### 🟠 HIGH-4 — HTML Report Claims "Interactive Tables" — They Aren't

**README says:** "Interactive Tables: Search, filter, and sort by host, port, or severity."  
**Reality:** The HTML template in `reporter.py` is a static table with no JavaScript, no search box, no filter controls, and no sort functionality. This is a plain `<table>` with CSS.

---

### 🟡 MEDIUM-5 — "Zero False Positives" CVE Matching Claim

**README says:** "Hardened Service & CVE matching logic (Zero false positives in v1.2.0)"  
**Reality:** The wildcard `version: "*"` entries in `cve_db.csv` will match any detected version string — including `"unknown"`. Every open SSH port, regardless of actual software version, will receive `CVE-2023-38408` (OpenSSH RCE). This is a false positive for any non-OpenSSH SSH daemon (Dropbear, libssh, etc.) and for systems where version detection fails.

---

### 🟢 LOW-6 — `pyproject.toml` Missing (README implies `netscope` as command)

**README usage section says:** `netscope [-h] -t TARGET ...`  
**Reality:** No `pyproject.toml`, no `setup.py`, no `setup.cfg`. The tool must be run as `python main.py`. The `netscope` command does not exist anywhere in the repo.

---

## Section 2 — Code Bugs

### 🔴 CRITICAL-7 — `calculate_risk_score` Ignores `cvss_score` in Test Fixtures

The `TestCalculateRiskScore` tests pass dicts with only `{"severity": "Critical"}` — no `cvss_score` key. The CVSS path (`cvss = v.get("cvss_score")`) returns `None`, so all tests exercise only the fallback severity-weight path. The actual CVSS v3.1 scoring logic is **never tested**.

Similarly the `test_single_critical` assertion `score > 9.0` passes because the fallback weight is `10.0`, not because CVSS integration works. A broken CVSS path would not be caught.

---

### 🔴 CRITICAL-8 — Nmap Uses `-O` (OS Detection) Without Root — Will Silently Fail or Error

In `engine.py`:
```python
args = f"-sV -T{timing} --version-intensity 5 -O --script=banner"
```
`-O` requires raw socket privileges (`root`/`CAP_NET_RAW`). Without them, Nmap prints a warning and skips OS detection but the scan continues — however the exception handling catches and silently logs this at WARNING level. On Linux without root, `-O` causes Nmap to emit an error message that python-nmap may misparse. More importantly, the README says nothing about root being required for Nmap enrichment, while the Docker image runs as non-root user `netscope`. Result: Nmap enrichment silently degrades without any user-visible warning.

---

### 🟠 HIGH-9 — Nmap `timeout=120` Is a Hard-Coded Global Limit

```python
nm.scan(host, ports=port_str, arguments=args, timeout=120)
```
For a host with many open ports split across multiple chunks, the total Nmap time is `n_chunks × 120s`. For `top1000` mode this is 10 chunks × 120s = up to 20 minutes of blocking per host. The user-visible `--timeout` flag does not influence Nmap's timeout. This is a UX trap.

---

### 🟠 HIGH-10 — `_check_port`: ConnectionResetError Returns `None` (Misses Filtered Ports)

```python
except ConnectionResetError:
    # If the server resets ... it is effectively closed/filtered.
    return None
```
An RST response means the port is **closed**, not filtered. More critically, a TCP RST is a definitive "host is alive and port is closed" signal — but returning `None` here means that port will never appear in results even if the host is alive. This is architecturally correct for the scanner (we only want open ports) but the comment is wrong and misleading. It says "filtered" when it means "rejected/closed."

---

### 🟠 HIGH-11 — HTTP Probe Sent to All Ports Including TLS Ports

```python
probe = f"HEAD / HTTP/1.0\r\nHost: {host}\\r\\n\\r\\n".encode()
writer.write(probe)
```
This plain-text HTTP probe is sent to **every port** with no banner. Port 443 (HTTPS), 8443, 465 (SMTPS), 993 (IMAPS), and any other TLS port will receive a cleartext HTTP probe, causing TLS handshake errors. The scanner gets a garbled response or `OSError`, the banner stays empty, and service identification falls back to port-number guessing. There is no TLS handshake path.

---

### 🟡 MEDIUM-12 — `datetime.utcnow()` Used Everywhere (Deprecated in Python 3.12+)

Found in 5 locations across `engine.py` and `reporter.py`. Python 3.12 emits `DeprecationWarning` for `datetime.utcnow()`. The tests generate **64 warnings** from this alone. Fix: use `datetime.now(datetime.UTC)`.

```
# 64 warnings in test run:
DeprecationWarning: datetime.datetime.utcnow() is deprecated
```

---

### 🟡 MEDIUM-13 — `_apply_yaml` Uses `setattr` Without Type Coercion

```python
for key, val in data.items():
    if hasattr(self, key):
        setattr(self, key, val)
```
YAML's `safe_load` returns native Python types (int, float, str, list). If a user writes `timeout: "1.5"` (quoted), they get a string instead of a float, which will crash `asyncio.wait_for(..., timeout="1.5")`. There is no type-checking or coercion on YAML values.

---

### 🟡 MEDIUM-14 — `_read_arp_cache_all_sync` Parses ARP Output Incorrectly on Linux

```python
parts = line.split()
if len(parts) >= 2:
    ip_raw = parts[0].strip("()")
    mac = parts[1].replace("-", ":")
```
On Linux, `arp -n` output format is:
```
Address         HWtype  HWaddress           Flags Mask  Iface
192.168.1.1     ether   aa:bb:cc:dd:ee:ff   C           eth0
```
`parts[1]` is `HWtype` (e.g. `"ether"`), not the MAC. The MAC is `parts[2]`. This function always extracts the wrong column on Linux, returning `"ether"` as the MAC address for every host. **ARP-based host discovery is broken on Linux.**

---

### 🟡 MEDIUM-15 — `scan_host_async` Semaphore Scoped Per-Host But Concurrency Is Global

```python
# In scan_host_async:
semaphore = asyncio.Semaphore(concurrency)
```
A new semaphore is created per `scan_host_async` call. When the scanner runs `host_batch_size=20` hosts in parallel (each with their own semaphore allowing 500 concurrent connections), the actual maximum concurrent connections is `20 × 500 = 10,000`. The `--concurrency` flag does not limit total connections — only per-host connections. On a slow link this can cause OS-level "too many open files" errors.

---

### 🟡 MEDIUM-16 — Version Matching Uses `in` (Substring, Not Semver)

```python
if entry["version"] == "*" or (
    version != "unknown" and entry["version"] in version
):
```
`entry["version"] = "5.5"` will match any detected version string containing "5.5", including "5.50", "15.5", "2.5.5". A detected version of `"MySQL 8.0.35"` would match a CVE entry for version `"0.3"` because `"0.3"` is in `"8.0.35"`. This produces false positives.

---

### 🟢 LOW-17 — `identify_service` Redis Pattern Has Ambiguity

```python
(r"^\\-ERR|^\\+OK", "redis"),
```
`+OK` is also a valid POP3 response. Since banner patterns are evaluated in order and `pop3` pattern (`r"^\\+OK"`) comes earlier in the list, Redis and POP3 clash. A Redis instance returning `+OK` would match POP3 if `^\\+OK` appears first. The order dependency is fragile.

---

### 🟢 LOW-18 — `TOP_1000_PORTS` Is Not Actually the Top 1000

```python
TOP_1000_PORTS: List[int] = list(range(1, 1025)) + [
    1433, 1521, 1723, 2049, ...
]
```
`range(1, 1025)` = 1024 ports, plus 14 extras = 1038 total. The name implies Nmap's canonical top-1000 list (which uses frequency data), but this is just sequential ports 1-1024 plus some common database ports. The actual Nmap top-1000 list is frequency-ordered and includes many high ports (e.g., 8888, 31337) that this list misses.

---

## Section 3 — Architecture & Design Issues

### 🔴 CRITICAL-19 — `engine.py` Is a 990-Line God Module

The entire scanner logic lives in one 990-line file: data models, validation, port scanning, banner grabbing, Nmap integration, CVE database, risk scoring, ARP utilities, and the main orchestrator class. This violates single-responsibility principle and makes the codebase hard to extend, test in isolation, or contribute to. The original audit spec called for splitting into `scanner/`, `discovery/`, `fingerprinting/`, `vulnerability/`, etc. — none of that has been done.

---

### 🟠 HIGH-20 — No Plugin/Extension Architecture

There is no way to add new banner grabbers, exporters, or enrichment providers without editing `engine.py` directly. The roadmap mentions extensibility but the architecture has no hooks, no abstract base classes, and no entry points for extensions.

---

### 🟠 HIGH-21 — `ScanSummary.results` Stores Full Vuln Objects in Memory

For a /16 network scan (65k hosts) with 50 open ports each and 10 CVEs each, `results` would hold `~32.5M` `PortResult` objects in RAM simultaneously. There is no streaming, no pagination, no partial writes, and no memory ceiling. Large network scans will OOM.

---

### 🟠 HIGH-22 — No Scan Session ID, No Metadata in Output

Reports have no:
- Unique scan session ID (for correlation)
- Tool version (`v2.0.0`) embedded in output
- CLI command used to generate the scan
- Config file path/hash used
- Scanner host (machine running the scan)
- Legal/authorization acknowledgment record

A professional pentest report must be reproducible. Without this metadata you can't answer "what options produced this report?"

---

### 🟠 HIGH-23 — No Allowlist/Blocklist for Accidental Scan Prevention

Nothing prevents `python main.py -t 8.8.8.8` or `python main.py -t 0.0.0.0/0`. There is a /16 CIDR limit but no:
- Blocklist for RFC1918 vs. public IP confirmation
- Legal confirmation prompt for non-private IP ranges
- `--authorize-scan` flag for CI pipelines
- Hardcoded blocks for `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4` (multicast)

---

### 🟠 HIGH-24 — No Rate Limiting or Jitter Between Probes

All ports on a host are scanned as fast as the semaphore allows, with no inter-probe delay. For internet-facing targets this will:
1. Trigger IDS/IPS and get the scanner IP blocked
2. Cause rate-limit responses that look like closed ports (false negatives)
3. Potentially overwhelm small devices

There is no `--polite-mode`, no jitter option, and no retry policy for timed-out ports.

---

### 🟡 MEDIUM-25 — Discovery Mode Does Not Feed Into Port Scan

`--discover` exits after discovery. There is no way to do: "discover alive hosts, then port-scan only those." The user must run discovery, manually compile the alive hosts list, then run port scans. For a /24 with 10 alive hosts out of 254, this means the scanner still attempts connections to 244 dead hosts during the port scan phase.

---

### 🟡 MEDIUM-26 — No Baseline Comparison

The roadmap mentions "Time-Series Subnet Analysis" but there is zero infrastructure for it: no scan history, no previous-scan storage, no diff between current and last scan. A `--compare last` flag that shows newly opened/closed ports would be high-value for network monitoring.

---

### 🟡 MEDIUM-27 — Reports Have No Remediation Guidance

The HTML/JSON/CSV reports show CVE IDs and risk scores but no:
- Remediation steps ("Update OpenSSH to ≥9.3", "Disable anonymous FTP")
- References (NVD URL, vendor advisory link)
- Confidence level (version matched vs. wildcard-matched)
- Evidence field (which banner triggered the match)
- Executive summary section

For a professional deliverable these are essential.

---

## Section 4 — Missing Features (Roadmap vs. Reality)

| Feature | README/Roadmap Status | Actual Status |
|---------|----------------------|---------------|
| UDP scanning | "[ ] UDP scanning support" | ❌ Not started |
| gRPC/REST API | "[ ] gRPC / REST API mode" | ❌ Not started |
| Web UI (React+FastAPI) | "[ ] Web UI" | ❌ Not started |
| NVD API/feed sync | Not in roadmap | ❌ Not started |
| TLS/HTTPS probing | Not in roadmap | ❌ Not started |
| Shodan integration | Listed in `config.py` field | ❌ Field exists, no code |
| IPv6 support | Not mentioned | ❌ `ip_network(..., AF_INET)` only |
| Scan profiles (safe/aggressive) | Not in roadmap | ❌ Not started |
| Protocol-specific banner probes | Not in roadmap | ❌ HTTP probe only |
| pyproject.toml packaging | Not in roadmap | ❌ Not started |
| GitHub Actions CI | Not in roadmap | ❌ No `.github/` folder |
| CHANGELOG.md | Standard | ❌ Missing |
| CONTRIBUTING.md | Standard | ❌ Missing |
| SECURITY.md | Standard | ❌ Missing |
| Pre-commit config | Not mentioned | ❌ Missing |
| Report signing/hash | Not mentioned | ❌ Missing |
| Distributed scanning | "[ ] Distributed Deployments" | ❌ Not started |

---

## Section 5 — Testing Gaps

### 🔴 CRITICAL-28 — Zero Tests for the Following Critical Paths

| Untested Code Path | Risk |
|-------------------|------|
| `_try_nmap_scan()` | Core enrichment feature entirely untested |
| `_try_nmap_discovery()` | Discovery booster untested |
| `run_discovery()` | Full discovery workflow untested |
| `_ping_host()` | ICMP discovery untested |
| `_nudge_host()` | TCP nudge untested |
| `_read_arp_cache_sync()` | ARP lookup untested |
| `_read_arp_cache_all_sync()` | Also contains Linux bug (see MEDIUM-14) — untested |
| `setup_logging()` in `log_config.py` | 0% coverage |
| CVSS v3.1 score path in `calculate_risk_score` | Logic exists but never called in tests |
| `validate_target` with IPv6 | Will fail with `AF_INET`-only socket calls |
| `validate_target` with hostname that resolves to multiple IPs | Partially tested |
| YAML type coercion errors | Not tested |
| KeyboardInterrupt cleanup | Not tested |
| Semaphore exhaustion under load | Not tested |
| `export_all` with unknown format | Only WARNING logged, not tested |

---

### 🟡 MEDIUM-29 — Tests Don't Verify Actual Report File Content Thoroughly

`test_html_report` checks `"10.0.0.1" in content` and `"CVE-2016-0777" in content`. It does not verify:
- Risk score rendered correctly
- Severity badges present
- Scan metadata (start/end times) present
- Multiple hosts render correctly
- HTML is valid (no unclosed tags)

---

## Section 6 — Security Issues in the Scanner Itself

### 🔴 CRITICAL-30 — Banner Content Written to Reports Without Sanitization in CSV/JSON

In `reporter.py`:
```python
# CSV
r.banner[:200]   # ← raw, no sanitization

# JSON
"banner": self.banner   # ← raw, no sanitization
```
HTML output does escape banners (`html_lib.escape`), but JSON and CSV output write raw banner content. A malicious host can serve a banner containing CSV injection (`=CMD|' /C calc'!A0`), ANSI escape sequences, null bytes, or Unicode control characters. This could compromise anyone who opens the CSV in Excel or processes the JSON in a downstream tool.

---

### 🟠 HIGH-31 — No Input Sanitization on `--config` Path

```python
_ = ScanConfig.load(args.config)
```
The config path is passed directly to `Path(path).open()`. While this doesn't execute code, a path traversal like `--config /etc/passwd` would attempt to parse `/etc/passwd` as YAML and log a parse error — leaking that the file exists and is readable. Minor but worth noting for Docker/CI contexts.

---

### 🟠 HIGH-32 — Shodan API Key Logged at DEBUG Level Risk

The `ScanConfig._apply_env()` reads `NETSCOPE_SHODAN_KEY` into `self.shodan_api_key`. While not directly logged, if someone adds `logger.debug("Config: %s", config)` (a common debugging pattern), the key will appear in log files. The key should be stored in a separate secrets field that is masked in `__repr__`/`__str__`.

---

### 🟡 MEDIUM-33 — Docker Image Copies Entire Repo Including `config/settings.yaml`

```dockerfile
COPY . .
```
If `config/settings.yaml` exists locally with a real Shodan key or custom CVE DB, it is baked into the Docker image. Anyone who pulls the image gets those secrets. Should use `.dockerignore` or explicit `COPY` commands.

---

## Section 7 — Dependencies & Packaging

### 🟠 HIGH-34 — `requests` in `requirements.txt` Is Unused

```
requests>=2.31.0   # HTTP client for Shodan integration
```
There is no Shodan integration code anywhere. `requests` is imported nowhere in the codebase. It adds ~500KB and a supply chain dependency for zero benefit.

---

### 🟠 HIGH-35 — No `pyproject.toml`, No Installable Package

The project cannot be installed with `pip install .` or `pip install -e .`. There is no entry point for the `netscope` command the README describes. No package metadata (author, license, Python requires, classifiers). No version constant importable from the package (`from netscope import __version__`).

---

### 🟠 HIGH-36 — No CI Pipeline

No `.github/workflows/` directory exists. There are no automated checks for:
- Lint (Ruff/Flake8)
- Type checking (Mypy)
- Tests (pytest)
- Coverage enforcement
- Security scanning (Bandit, pip-audit)
- Docker build verification

The README CI example is illustrative only — it shows how to *use* NetScope in CI, not how to test NetScope itself.

---

### 🟡 MEDIUM-37 — Dev Dependencies Are Minimal

`requirements-dev.txt` only has `pytest`, `pytest-asyncio`, and `pytest-cov`. Missing:
- `ruff` or `flake8` (linting)
- `mypy` (type checking)
- `bandit` (security scanning)
- `pip-audit` (dependency vulnerability scanning)
- `pre-commit` (git hooks)
- `black` (formatting)

---

### 🟡 MEDIUM-38 — No `.gitignore` Visible, No `MANIFEST.in`

The repo structure shows no `.gitignore`. Reports and logs may accidentally be committed. The `config/settings.yaml` (with potential API keys) is not gitignored.

---

## Section 8 — Documentation Issues

### 🟠 HIGH-39 — No Sample Reports or Screenshots

The README has no screenshots of the HTML report, no example JSON output, and no sample CSV. A recruiter or hiring manager evaluating this portfolio piece cannot see what the tool actually produces without cloning and running it.

---

### 🟠 HIGH-40 — Architecture Diagram Is Mermaid in README (Not Rendered on GitHub)

The Mermaid diagram in the README will only render on GitHub if the repo has the Mermaid GitHub Actions integration or uses GitHub's native Mermaid support (which it does, actually — GitHub renders Mermaid in markdown). This is fine. But there is no standalone architecture diagram file, no `docs/` folder, and no API reference.

---

### 🟡 MEDIUM-41 — Windows Compatibility Notes Are Incomplete

The README says "Download installer from nmap.org" for Windows but does not mention:
- `asyncio.create_subprocess_exec` behavior on Windows (different event loop policy required for Python <3.12)
- ARP command differences (`arp -a` on Windows doesn't have the same output as Linux)
- Path separator issues (`config/cve_db.csv` vs `config\\cve_db.csv`)
- `CREATE_NO_WINDOW` flag (already used in code, not documented)

---

### 🟡 MEDIUM-42 — CVE Database Is Tiny and Static

The bundled `cve_db.csv` has ~30 entries. There is no update mechanism, no NVD sync, no freshness indicator, and no documentation on how to extend it. For a "production-grade" tool this is a significant gap — real scanners update vulnerability databases automatically.

---

## Section 9 — Summary Matrix

| # | Issue | Severity | File | Effort to Fix |
|---|-------|----------|------|---------------|
| 1 | Coverage claim wrong (69% not 94%) | 🔴 CRITICAL | README.md | Low (fix README) or High (write tests) |
| 2 | Config loaded but discarded — YAML/env ignored | 🔴 CRITICAL | main.py | Medium |
| 3 | YAML key mismatch `batch_size` vs `host_batch_size` | 🟠 HIGH | README.md | Low |
| 4 | "Interactive tables" claim false | 🟠 HIGH | README.md, reporter.py | Medium (add JS) |
| 5 | Wildcard CVE matching produces false positives | 🟡 MEDIUM | cve_db.csv, engine.py | Medium |
| 6 | `netscope` command doesn't exist (no pyproject.toml) | 🟢 LOW→HIGH | — | Medium |
| 7 | CVSS scoring path untested | 🔴 CRITICAL | tests/ | Low |
| 8 | Nmap `-O` silently fails without root | 🔴 CRITICAL | engine.py | Low |
| 9 | Nmap 120s timeout unconfigurable | 🟠 HIGH | engine.py | Low |
| 10 | ConnectionResetError comment wrong | 🟡 MEDIUM | engine.py | Trivial |
| 11 | HTTP probe sent to TLS ports | 🟠 HIGH | engine.py | Medium |
| 12 | `datetime.utcnow()` deprecated (64 warnings) | 🟡 MEDIUM | engine.py, reporter.py | Low |
| 13 | YAML values not type-coerced | 🟡 MEDIUM | config.py | Low |
| 14 | ARP parsing wrong on Linux (wrong column) | 🟡 MEDIUM | engine.py | Low |
| 15 | Semaphore per-host, not global | 🟡 MEDIUM | engine.py | Medium |
| 16 | Version matching uses substring `in` | 🟡 MEDIUM | engine.py | Medium |
| 17 | Redis/POP3 banner pattern ambiguity | 🟢 LOW | engine.py | Trivial |
| 18 | TOP_1000_PORTS is not real Nmap top-1000 | 🟢 LOW | config.py | Low |
| 19 | 990-line god module | 🔴 CRITICAL | engine.py | High |
| 20 | No plugin architecture | 🟠 HIGH | — | High |
| 21 | No memory ceiling for large scans | 🟠 HIGH | engine.py | High |
| 22 | No scan session ID/metadata in reports | 🟠 HIGH | engine.py, reporter.py | Low |
| 23 | No allowlist/blocklist | 🟠 HIGH | engine.py, main.py | Medium |
| 24 | No rate limiting or jitter | 🟠 HIGH | engine.py | Medium |
| 25 | Discovery doesn't feed port scan | 🟡 MEDIUM | main.py | Medium |
| 26 | No baseline/diff comparison | 🟡 MEDIUM | — | High |
| 27 | No remediation guidance in reports | 🟡 MEDIUM | reporter.py, cve_db.csv | Medium |
| 28 | Zero tests for discovery/Nmap/ARP | 🔴 CRITICAL | tests/ | High |
| 29 | Report tests too shallow | 🟡 MEDIUM | tests/ | Low |
| 30 | CSV/JSON banners not sanitized | 🔴 CRITICAL | reporter.py | Low |
| 31 | `--config` path not validated | 🟠 HIGH | main.py | Low |
| 32 | API key masking missing | 🟠 HIGH | config.py | Low |
| 33 | `COPY .` in Dockerfile bakes secrets | 🟡 MEDIUM | Dockerfile | Low |
| 34 | `requests` is unused dependency | 🟠 HIGH | requirements.txt | Trivial |
| 35 | No pyproject.toml packaging | 🟠 HIGH | — | Medium |
| 36 | No GitHub Actions CI | 🟠 HIGH | — | Medium |
| 37 | Dev dependencies minimal | 🟡 MEDIUM | requirements-dev.txt | Low |
| 38 | No .gitignore visible | 🟡 MEDIUM | — | Low |
| 39 | No sample reports/screenshots | 🟠 HIGH | README.md | Medium |
| 40 | No docs/ folder | 🟡 MEDIUM | — | Medium |
| 41 | Windows compat notes incomplete | 🟡 MEDIUM | README.md | Low |
| 42 | CVE DB tiny and static, no update mechanism | 🟠 HIGH | config/ | High |

**Totals: 8 🔴 CRITICAL · 16 🟠 HIGH · 16 🟡 MEDIUM · 3 🟢 LOW**

---

## Section 10 — Recommended Upgrade Priority

### Phase A — Fix False Claims (1–2 days)
1. Correct coverage claim in README (69%, not 94%)
2. Fix `main.py` to actually apply `ScanConfig` values (CRITICAL-2)
3. Fix YAML key mismatch `batch_size` → `host_batch_size`
4. Remove unused `requests` dependency
5. Replace all `datetime.utcnow()` with `datetime.now(datetime.UTC)`
6. Fix Linux ARP parsing (wrong column index)
7. Remove `-O` from default Nmap args, add `--nmap-os-detect` flag with root warning

### Phase B — Critical Security & Quality (3–5 days)
8. Sanitize banners in CSV and JSON output
9. Add `pyproject.toml` with entry point for `netscope` command
10. Add scan session UUID, version, and command metadata to all reports
11. Write tests for CVSS scoring path, log_config, and discovery functions
12. Add TLS/HTTPS detection (detect TLS on connection, skip HTTP probe for TLS ports)
13. Fix semaphore scope (global semaphore, not per-host)
14. Add `.dockerignore` to prevent secret baking

### Phase C — Feature Completeness (1–2 weeks)
15. Add GitHub Actions CI (lint, test, coverage, bandit, pip-audit, docker build)
16. Add allowlist/blocklist with legal confirmation for public IP ranges
17. Add rate limiting and jitter options
18. Add NVD API/feed sync for CVE database updates
19. Add protocol-specific banner probes (TLS, SSH, FTP, SMTP, Redis, MySQL)
20. Add remediation guidance and CVSS references to reports
21. Add baseline comparison (`--compare` flag with stored previous scan)
22. Split `engine.py` into proper modules

### Phase D — Portfolio Polish (1 week)
23. Add JavaScript search/filter/sort to HTML report (fulfill README claim)
24. Generate and commit sample reports
25. Add `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`
26. Add architecture diagram as PNG in `docs/`
27. Add Mypy strict type checking
28. Add pre-commit hooks (ruff, mypy, bandit)

---

*End of audit. Total findings: 42. All findings are based on static code analysis and live test execution against the committed codebase.*
