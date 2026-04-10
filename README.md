# 🔍 NetScope — Network Vulnerability Scanner

A production-grade, async network vulnerability scanner built in Python.  
Designed for security professionals, network administrators, and penetration testers.

> ⚠️ **Legal Notice:** Only scan networks and hosts you own or have **explicit written permission** to test.
> Unauthorized port scanning may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide.

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Configuration](#configuration)
7. [Reports](#reports)
8. [Testing](#testing)
9. [Deployment](#deployment)
10. [Security Considerations](#security)
11. [Roadmap](#roadmap)

---

## Features

| Category | Capability |
|---|---|
| **Scanning** | Async TCP connect scan (asyncio), optional Nmap SV/OS enrichment |
| **Detection** | Banner grabbing with HTTP probe fallback, regex-based service/version fingerprinting |
| **Intelligence** | Local CVE CSV database matching (wildcard + version-specific), Shodan API hook |
| **Reporting** | HTML (dark-mode, interactive), JSON (structured), CSV (spreadsheet-ready) |
| **Safety** | Input validation, CIDR limit (/16 max), XSS-escaped HTML output, non-root Docker |
| **Ops** | Rotating file + colourised console logging, YAML config, env-var overrides |
| **Testing** | 22+ unit tests covering all modules, real socket integration tests |
| **Deployment** | Docker + Docker Compose with `network_mode: host` and `NET_RAW` capability |

---

## Architecture

```
netscope/
├── main.py                    # CLI entry point
├── config/
│   ├── settings.yaml          # Default configuration
│   └── cve_db.csv             # Local CVE database (extensible)
├── src/
│   ├── scanner/
│   │   └── engine.py          # Core: async scanning, Nmap, CVE matching, risk scoring
│   ├── reporting/
│   │   └── reporter.py        # HTML / JSON / CSV exporters
│   └── utils/
│       ├── config.py          # ScanConfig dataclass + env/YAML loader
│       └── log_config.py      # Structured logging (console + rotating file)
├── tests/
│   └── test_netscope.py       # Unit + integration tests (pytest)
├── reports/                   # Generated reports (gitignored)
├── logs/                      # Log files (gitignored)
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

### Data Flow

```
CLI args / config
       │
       ▼
 NetScopeScanner.run()
       │
       ├── validate_target()        → List[str] of IPs
       ├── validate_ports()         → List[int] of ports
       │
       ▼
 scan_host_async()                  (asyncio, semaphore-bounded)
       │  per open port:
       ├── banner grab (TCP recv + HTTP probe)
       ├── _try_nmap_scan()         (thread pool, optional)
       │
       ▼
 _build_port_result()
       ├── identify_service()       (banner regex → port map)
       ├── parse_version()          (regex extraction)
       ├── CveDatabase.match()      (CVE lookup)
       └── calculate_risk_score()   (weighted severity formula)
       │
       ▼
 ScanSummary
       │
       ▼
 export_all()
       ├── generate_html()
       ├── generate_json()
       └── generate_csv()
```

---


---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Ayaan-22/NetScope.git
cd netscope

# 2. Install
pip install -r requirements.txt
sudo apt-get install nmap   # or: brew install nmap

# 3. Scan
python main.py -t 192.168.1.1

# 4. Open report
open reports/netscope_*.html
```

---

## Installation

### Local (Python 3.10+)

```bash
pip install -r requirements.txt
```

**System Nmap** (required for service/version detection):
```bash
# Debian / Ubuntu
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
# Download installer from https://nmap.org/download.html
```

> If Nmap is not installed, NetScope falls back gracefully to async TCP scanning only. Pass `--no-nmap` to skip Nmap explicitly.

### Docker

```bash
docker build -t netscope .
docker run --rm --network host netscope -t 192.168.1.1
```

---

## Usage

```
usage: netscope [-h] -t TARGET [-p PORTS] [--timeout SECS]
                [--concurrency N] [--no-nmap] [--nmap-timing {0-5}]
                [--cve-db PATH] [--output-dir DIR]
                [--formats {html,json,csv} [...]] [--log-level LEVEL]
```

### Examples

```bash
# Single host, default common ports
python main.py -t 192.168.1.1

# Subnet with custom ports
python main.py -t 192.168.1.0/24 -p 22,80,443,8080-8090

# Full network scan (all ports)
python main.py -t 192.168.1.0/24 -p all

# Top 1000 ports, skip Nmap, HTML report only
python main.py -t 10.0.0.5 --ports top1000 --no-nmap --formats html

# Fast scan with high concurrency (LAN only — be careful on WAN)
python main.py -t 10.0.0.0/24 --concurrency 1000 --timeout 0.8

# Quiet mode, debug logging to file
python main.py -t 10.0.0.1 --log-level WARNING

# Custom CVE database and output directory
python main.py -t 192.168.1.1 --cve-db /data/nvd_export.csv --output-dir /tmp/scans
```

### Port Specifications

| Spec | Meaning |
|---|---|
| `common` | 25 well-known ports (default) |
| `top1000` | Top ~1000 ports (nmap-style) |
| `all` | All 65,535 TCP ports |
| `80` | Single port |
| `22,80,443` | Comma-separated list |
| `1-1024` | Range |
| `22,80,8000-8090` | Mixed |

---

## Configuration

### YAML (`config/settings.yaml`)

```yaml
timeout: 1.5
concurrency: 500
use_nmap: true
nmap_timing: 4
cve_db_path: config/cve_db.csv
output_dir: reports
report_formats: [html, json, csv]
log_level: INFO
```

### Environment Variables

All settings can be overridden via env vars (useful for Docker/CI):

| Variable | Default | Description |
|---|---|---|
| `NETSCOPE_TIMEOUT` | `1.5` | Per-port TCP timeout (seconds) |
| `NETSCOPE_CONCURRENCY` | `500` | Max async connections |
| `NETSCOPE_USE_NMAP` | `1` | Set to `0` to disable Nmap |
| `NETSCOPE_NMAP_TIMING` | `4` | Nmap timing template (0–5) |
| `NETSCOPE_CVE_DB` | `config/cve_db.csv` | Path to CVE database |
| `NETSCOPE_SHODAN_KEY` | _(empty)_ | Shodan API key |
| `NETSCOPE_OUTPUT_DIR` | `reports` | Report output directory |
| `NETSCOPE_LOG_LEVEL` | `INFO` | Logging level |

### CVE Database Format

The CVE database is a plain CSV file at `config/cve_db.csv`.  
You can extend it with your own entries or import from NVD exports.

```csv
service,version,cve_id,description,severity
ssh,7.2,CVE-2016-0777,OpenSSH 7.2 roaming connection memory disclosure,High
ssh,*,CVE-2023-38408,OpenSSH remote code execution via ssh-agent,Critical
http,*,CVE-2021-41773,Apache 2.4.49 path traversal and RCE,Critical
```

- **`version`**: Use `*` to match any version, or a substring like `7.2` to match `7.2.x`
- **`severity`**: `Critical` / `High` / `Medium` / `Low` / `Info`
- **`service`**: Lowercase service name matching banner detection output

---

## Reports

Three formats are generated on every scan (all to `reports/`):

### HTML Report
Dark-mode, browser-viewable report with:
- Summary statistics cards
- High-risk host alert banner
- Per-port table: host, port, service, version, risk score, banner preview, CVE list
- Colour-coded severity badges and risk scores

### JSON Report
Machine-readable, suitable for ingestion into SIEMs, dashboards, or CI pipelines:
```json
{
  "meta": { "target": "...", "hosts_scanned": 1, "total_vulnerabilities": 3, ... },
  "results": [
    { "host": "10.0.0.1", "port": 22, "service": "ssh", "risk_score": 8.5,
      "vulnerabilities": [{ "cve_id": "CVE-2023-38408", "severity": "Critical", ... }] }
  ]
}
```

### CSV Report
One row per open port. Importable into Excel, Splunk, or any SIEM.

---

## Testing

```bash
# With pytest installed:
pytest tests/ -v --tb=short

# Without pytest (built-in runner):
python3 -m unittest discover tests/

# Coverage report:
pytest tests/ --cov=src --cov-report=html
```

### Test Coverage

| Module | Tests |
|---|---|
| `validate_target` | valid IP, CIDR /30, network too large, empty, invalid |
| `validate_ports` | list, range, mixed, dedup, port 0, inverted range |
| `identify_service` | SSH/HTTP/FTP banner match, port fallback, unknown |
| `parse_version` | semver, 3-part, version keyword, no match |
| `calculate_risk_score` | empty, critical, low, many medium, capped at 10, unknown severity |
| `CveDatabase` | wildcard match, version match, no match, missing file, family match |
| Async scanner | open port detected with real server, closed port ignored, multi-port |
| HTML report | content present, XSS escaped |
| JSON report | structure and values |
| CSV report | headers and row values |

---

## Deployment

### Docker (Recommended)

```bash
# Build
docker build -t netscope:latest .

# Single scan
docker run --rm --network host \
  -v $(pwd)/reports:/app/reports \
  netscope:latest -t 192.168.1.0/24

# With Shodan
docker run --rm --network host \
  -e NETSCOPE_SHODAN_KEY=your_key \
  -v $(pwd)/reports:/app/reports \
  netscope:latest -t 192.168.1.1
```

### Docker Compose

```bash
# Edit docker-compose.yml to set your target, then:
docker compose run netscope -t 192.168.1.0/24 --formats html json
```

### CI / Scheduled Scanning

```yaml
# .github/workflows/scan.yml
- name: Run NetScope
  run: |
    docker run --rm --network host \
      -v ${{ github.workspace }}/reports:/app/reports \
      netscope:latest -t ${{ secrets.SCAN_TARGET }} \
      --formats json
- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: scan-report
    path: reports/
```

### Recommended Production Configuration

```yaml
# High-accuracy LAN scan
timeout: 2.0
concurrency: 300      # Lower if hitting rate limits / firewalls
nmap_timing: 3        # Slightly slower, more accurate
use_nmap: true

# Fast internet-facing scan
timeout: 3.0
concurrency: 100      # Be polite on WAN
nmap_timing: 2
use_nmap: false       # Skip Nmap for stealth/speed
```

---

## Security Considerations

1. **Run as non-root** unless Nmap SYN scanning is required (`NET_RAW` capability). The Docker image uses a dedicated `netscope` user.
2. **Never scan targets you don't own.** Store written authorisation alongside scan reports.
3. **Rate-limit on WAN.** Keep `--concurrency` ≤ 100 on internet targets to avoid triggering IDS/IPS or getting IP-blocked.
4. **Protect reports.** Reports contain sensitive infrastructure data. Store them in access-controlled directories; the `reports/` folder is gitignored by default.
5. **Rotate API keys.** The Shodan key is read from `NETSCOPE_SHODAN_KEY` — never commit it to source control.
6. **CVE DB is local.** The bundled database is a starting point. For production, sync against NVD or a commercial feed.

---

## Roadmap

- [ ] UDP scanning support
- [ ] NVD API integration for live CVE lookups
- [ ] Shodan enrichment (banner + CVEs) via `shodan` library
- [ ] gRPC / REST API mode for integration into security dashboards
- [ ] Web UI (React + FastAPI) for interactive scanning
- [ ] Scan diffing — compare two scan results and report new/changed/closed ports
- [ ] Notification hooks (Slack, PagerDuty, email) on critical findings
