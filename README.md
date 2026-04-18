# 🔍 NetScope - Network Vulnerability Scanner - v2.0.0

A production-grade, async network vulnerability scanner built in Python. Designed for security professionals, network administrators, and penetration testers.

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
7. [Host Discovery Engine](#host-discovery-engine)
8. [Reports](#reports)
9. [Testing](#testing)
10. [Deployment](#deployment)
11. [Security Considerations](#security-considerations)
12. [Roadmap](#roadmap)

---

## Features

| Category         | Capability                                                                           |
| ---------------- | ------------------------------------------------------------------------------------ |
| **Scanning**     | High-performance Async TCP connect scan, configurable batching and concurrency      |
| **Discovery**    | **High-Fidelity Engine**: ICMP sweep + **TCP Nudge** + Nmap ARP overlay             |
| **Detection**    | Banner grabbing with dynamic HTTP Host probing, regex-based fingerprinting          |
| **Intelligence** | **CVSS v3.1 Integration**: Local CVE database with authoritative NVD base scores     |
| **Reporting**    | Interactive HTML (Dark Mode), JSON (Machine-ready), and CSV (SIEM-ready)             |
| **Safety**       | CIDR limits (/16), XSS-escaped output, shared thread-pool lifecycle management      |
| **Ops**          | Rotating logs, YAML configuration, environment variable overrides                    |
| **Testing**      | **~94% Coverage**: Exhaustive unit and async integration test suite (`pytest`)       |

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
│   ├── test_netscope.py       # Core unit tests
│   └── test_phase3.py         # Advanced async & end-to-end integration tests (v1.2.0)
├── reports/                   # Generated reports (gitignored)
├── logs/                      # Log files (gitignored)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── requirements-dev.txt
```

### Data Flow

```
CLI args / config
       │
       ▼
  NetScopeScanner.run() / run_discovery()
       │
       ├── validate_target()        → List[str] of IPs (max /16)
       ├── validate_ports()         → List[int] of ports
       │
       ▼
 [if discovery] → run_discovery()
       ├── async ICMP ping sweep
       └── ARP table enrichment
 [if scan]      → batched execution (per --batch-size)
       │  for host in current_batch:
       ├── scan_host_async()        (asyncio, --concurrency bounded)
       │  per open port:
       │   ├── banner grab (TCP recv + HTTP Host probe)
       │   ├── _try_nmap_scan()     (shared ThreadPoolExecutor)
       │   └── CveDatabase.match()  (family-whitelisted matching)
       │
       ▼
 ScanSummary (metrics: targeted vs responded)
       │
       ▼
 export_all() (HTML / JSON / CSV)
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
usage: netscope [-h] -t TARGET [-p PORTS] [--discover] [--timeout SECS]
                [--concurrency N] [--batch-size N] [--no-nmap]
                [--nmap-timing {0-5}] [--cve-db PATH] [--output-dir DIR]
                [--formats {html,json,csv} [...]] [--log-level LEVEL]
                [--config FILE]
```

### Argument Details

| Flag            | Default         | Description                                              |
| --------------- | --------------- | -------------------------------------------------------- |
| `-t, --target`  | **Required**    | IP, hostname, or CIDR (e.g.`192.168.1.0/24`)             |
| `--discover`    | `false`         | Host discovery only (ping sweep + ARP), no port scan     |
| `-p, --ports`   | `common`        | `common`, `top1000`, `all`, or custom list (`22,80,443`) |
| `--timeout`     | `1.5`           | Connection timeout in seconds                            |
| `--concurrency` | `500`           | Max concurrent sockets (per host)                        |
| `--batch-size`  | `20`            | Max hosts scanned in parallel (total batch)              |
| `--no-nmap`     | `false`         | Skip Nmap service/version enrichment                     |
| `--config`      | `settings.yaml` | Path to YAML config file                                 |

````

### Examples

```bash
# Single host, default common ports
python main.py -t 192.168.1.1

# Subnet with custom ports
python main.py -t 192.168.1.0/24 -p 22,80,443,8080-8090

# Fast host discovery (ping sweep) - no port scanning
python main.py -t 192.168.1.0/24 --discover

# Full network scan (all ports)
python main.py -t 192.168.1.0/24 -p all

# Top 1000 ports, skip Nmap, HTML report only
python main.py -t 10.0.0.5 --ports top1000 --no-nmap --formats html

# High-performance LAN scan (Parallelise 100 hosts at once)
python main.py -t 10.0.0.0/24 --batch-size 100 --concurrency 1000

# Quiet mode, debug logging to file
python main.py -t 10.0.0.1 --log-level WARNING

# Custom configuration and output
python main.py -t 192.168.1.1 --config custom_prod.yaml --output-dir ./final_scans
````

### Port Specifications

| Spec              | Meaning                       |
| ----------------- | ----------------------------- |
| `common`          | 25 well-known ports (default) |
| `top1000`         | Top ~1000 ports (nmap-style)  |
| `all`             | All 65,535 TCP ports          |
| `80`              | Single port                   |
| `22,80,443`       | Comma-separated list          |
| `1-1024`          | Range                         |
| `22,80,8000-8090` | Mixed                         |

---

## Configuration

### YAML (`config/settings.yaml`)

```yaml
timeout: 1.5
concurrency: 500
batch_size: 20
use_nmap: true
nmap_timing: 4
cve_db_path: config/cve_db.csv
output_dir: reports
report_formats: [html, json, csv]
log_level: INFO
```

### Precedence Order

NetScope applies configuration in the following order (highest priority wins):

1. **Command Line Arguments** (`--timeout 2.0`)
2. **Environment Variables** (`NETSCOPE_TIMEOUT=2.0`)
3. **YAML Config File** (`timeout: 2.0`)
4. **Hard-coded Defaults** (`1.5`)

### Environment Variables

All settings can be overridden via env vars (useful for Docker/CI):

| Variable               | Default             | Description                    |
| ---------------------- | ------------------- | ------------------------------ |
| `NETSCOPE_TIMEOUT`     | `1.5`               | Per-port TCP timeout (seconds) |
| `NETSCOPE_CONCURRENCY` | `500`               | Max async connections          |
| `NETSCOPE_USE_NMAP`    | `1`                 | Set to `0` to disable Nmap     |
| `NETSCOPE_NMAP_TIMING` | `4`                 | Nmap timing template (0–5)     |
| `NETSCOPE_CVE_DB`      | `config/cve_db.csv` | Path to CVE database           |
| `NETSCOPE_SHODAN_KEY`  | _(empty)_           | Shodan API key                 |
| `NETSCOPE_OUTPUT_DIR`  | `reports`           | Report output directory        |
| `NETSCOPE_LOG_LEVEL`   | `INFO`              | Logging level                  |

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
- **`service`**: Lowercase service name matching banner detection output (e.g., `http`, `ssh`, `mysql`)

---

## Host Discovery Engine

The `--discover` flag provides a multi-layered, high-fidelity discovery sweep designed to map modern networks where standard pings are often blocked by mobile devices (iOS/Android) and hardened workstations.

### Multi-Layer Discovery Logic:

1.  **ICMP Ping Sweep**: Parallel async pings for foundational host enumeration.
2.  **TCP Nudge Strategy**: Attempts sub-second TCP connections to common ports (80, 443, 22, 5353, 62078). A response (SYN-ACK) or even a refusal (**RST**) provides a definitive "UP" signal and forces the target's MAC address into the system's ARP cache.
3.  **Nmap ARP Overlay**: If Nmap is installed, NetScope leverages its advanced discovery heuristics to find hosts that traditional methods might miss.
4.  **ARP Cache Resolution**: Reads the local ARP table to resolve MAC addresses and confirm host presence even if the host hides from active probes.

**Example:**

```bash
python main.py -t 192.168.1.0/24 --discover
```

Output includes:
- **IP Address**: The resolved IPv4.
- **MAC Address**: Resolved via the nudged ARP cache.
- **Hostname**: Resolved via reverse DNS.

## Reports

Three formats are generated on every scan (all to `reports/`):

### HTML Report

Interactive browser-viewable report features:
- **Risk Score Cards**: Quick scan summary of critical findings.
- **CVSS v3.1 Badges**: Automated NVD score matching (e.g., `Critical`, `High`).
- **Interactive Tables**: Search, filter, and sort by host, port, or severity.
- **Technical Evidence**: Full banner evidence and service versioning.

### JSON Report

Machine-readable, suitable for ingestion into SIEMs, dashboards, or CI pipelines. Now includes explicit host metrics.

```json
{
  "meta": {
    "target": "10.0.0.0/24",
    "hosts_targeted": 254,
    "hosts_with_results": 3,
    "total_vulnerabilities": 8,
    "scan_start": "2026-04-18T00:00:01",
    "scan_end": "2026-04-18T00:00:45"
  },
  "results": [
    { "host": "10.0.0.1", "port": 22, "service": "ssh", "risk_score": 8.5,
      "vulnerabilities": [{ "cve_id": "CVE-2023-38408", "severity": "Critical", ... }] }
  ]
}
```

### CSV Report

One row per open port. Importable into Excel, Splunk, or any SIEM. Fields include: Host, Port, Service, Version, Risk Score, CVE Count, and Banner.

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

| Module                 | Tests                                                                |
| ---------------------- | -------------------------------------------------------------------- |
| `validate_target`      | valid IP, CIDR /30, network too large, empty, invalid                |
| `validate_ports`       | list, range, mixed, dedup, port 0, inverted range                    |
| `identify_service`     | SSH/HTTP/FTP banner match, port fallback, unknown                    |
| `parse_version`        | semver, 3-part, version keyword, no match                            |
| `calculate_risk_score` | empty, critical, low, many medium, capped at 10, unknown severity    |
| `CveDatabase`          | wildcard match, version match, no match, missing file, family match  |
| Async scanner          | open port detected with real server, closed port ignored, multi-port |
| HTML report            | content present, XSS escaped                                         |
| JSON report            | structure and values                                                 |
| CSV report             | headers and row values                                               |

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

- [x] Async performance optimization (batched host scanning)
- [x] Configurable concurrency and batch sizes
- [x] Hardened Service & CVE matching logic (Zero false positives in `v1.2.0`)
- [x] High-density integration testing (~94% coverage)
- [ ] Distributed Deployments: Worker topology for massive cross-subnet sweeps on enterprise estates.
- [ ] Time-Series Subnet Analysis: Identify anomalous behavior (impromptu port openings) over sustained periods.
- [ ] Response Extensibility: Automated triggering of rapid verification scripts based on discovered CVE profiles.
- [ ] UDP scanning support
- [ ] gRPC / REST API mode for integration into security dashboards
- [ ] Web UI (React + FastAPI) for interactive scanning
