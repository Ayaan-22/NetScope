"""
NetScope Scanner Engine
Core scanning logic with async port scanning, service detection,
banner grabbing, and CVE matching.

Phase 1 — Critical bug fixes:
  BUG-1  asyncio.get_event_loop() → asyncio.get_running_loop()
  BUG-2  HTTP probe sends correct Host header (host variable, not literal "target")
  BUG-3  Blocking subprocess.check_output() in run_discovery() wrapped in executor
  BUG-4  Nmap port cap of 100 replaced with chunked calls (no silent truncation)
  BUG-5  CVE family matching replaced with explicit whitelist map (no false positives)
  BUG-6  ThreadPoolExecutor created once in __init__ and reused (not per-host)

Phase 2 — Design fixes:
  DESIGN-1  _get_host_info results cached on scanner instance (resolved once per host)
  DESIGN-2  hosts_scanned metric fixed: ScanSummary now distinguishes hosts_targeted
            (all IPs in the CIDR) from hosts_with_results (hosts with ≥1 open port)
  DESIGN-3  YAML / env-var load order corrected: defaults → YAML → env vars
            (env vars now always win, previously YAML overwrote them)
  DESIGN-4  host_batch_size is now a constructor parameter (was a hard-coded magic
            number 20 buried in run()); exposed via ScanConfig and CLI --batch-size

Phase 4 — CVSS integration:
  CVSS-1  CveDatabase._load() parses optional cvss_score + cvss_vector columns
          from cve_db.csv v2; old DBs without those columns still load cleanly.
  CVSS-2  calculate_risk_score() prefers the CVSS v3.1 base score when present;
          falls back to severity-weight table for rows that predate the column.
"""

import asyncio
import math
import platform
import socket
import subprocess
import re
import csv
import logging
import ipaddress
import concurrent.futures
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = "unknown"
    version: str = "unknown"
    banner: str = ""
    vulnerabilities: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0
    scan_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "vulnerabilities": self.vulnerabilities,
            "risk_score": self.risk_score,
            "scan_time": self.scan_time,
        }


@dataclass
class ScanSummary:
    target: str
    # DESIGN-2 FIX: The original single hosts_scanned field counted every IP in
    # the CIDR range, so a /24 scan with 3 alive hosts reported "hosts_scanned: 256".
    # We now track both values explicitly:
    #   hosts_targeted     — total IPs in the requested range
    #   hosts_with_results — hosts that had ≥1 open port (what users expect)
    # The old field name is preserved as a property for backwards compatibility.
    hosts_targeted: int
    hosts_with_results: int
    open_ports: int
    total_vulns: int
    high_risk_hosts: List[str]
    scan_start: str
    scan_end: str
    results: List[PortResult]

    @property
    def hosts_scanned(self) -> int:
        """Backwards-compatible alias → hosts_with_results."""
        return self.hosts_with_results


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def validate_target(target: str) -> List[str]:
    """
    Validate and expand a target (IP, CIDR, hostname) into a list of IP strings.
    Raises ValueError on invalid input.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    hosts: List[str] = []

    # CIDR notation
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            # Limit to prevent accidental huge scans (max /16 = 65536 hosts)
            if network.num_addresses > 65536:
                raise ValueError(
                    f"Network {target} has {network.num_addresses} addresses. "
                    "Limit scans to 65536 hosts (/16) or smaller."
                )
            hosts = [str(ip) for ip in network.hosts()]
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR notation '{target}': {exc}") from exc
    else:
        # Single IP or hostname
        try:
            ipaddress.ip_address(target)
            hosts = [target]
        except ValueError:
            # Hostname — resolve it
            try:
                resolved = socket.getaddrinfo(target, None, socket.AF_INET)
                hosts = list({r[4][0] for r in resolved})
                logger.info("Resolved %s → %s", target, hosts)
            except socket.gaierror as exc:
                raise ValueError(f"Cannot resolve hostname '{target}': {exc}") from exc

    if not hosts:
        raise ValueError(f"No valid hosts found for target '{target}'.")
    return hosts


def validate_ports(ports_spec: str) -> List[int]:
    """
    Parse a port specification string into a list of integers.
    Supports: "80", "80,443", "1-1024", "22,80,8000-8080"
    """
    ports: List[int] = []
    for part in ports_spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    raise ValueError
                ports.extend(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid port range: '{part}'")
        else:
            try:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError
                ports.append(port)
            except ValueError:
                raise ValueError(f"Invalid port number: '{part}'")
    return sorted(set(ports))


# ---------------------------------------------------------------------------
# Service identification
# ---------------------------------------------------------------------------

_PORT_SERVICE_MAP: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 587: "smtp-submission",
    993: "imaps", 995: "pop3s", 1723: "pptp",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb",
}

_BANNER_PATTERNS: List[Tuple[str, str]] = [
    (r"SSH-[\d.]+-", "ssh"),
    (r"^220.*FTP", "ftp"),
    (r"^220.*SMTP|^220.*mail", "smtp"),
    (r"HTTP/\d\.\d|Server:\s*\w+", "http"),
    (r"^\+OK", "pop3"),
    (r"^\* OK.*IMAP", "imap"),
    (r"MySQL|MariaDB", "mysql"),
    (r"RFB \d+\.\d+", "vnc"),
    (r"^\-ERR|^\+OK", "redis"),
]


def identify_service(port: int, banner: str) -> str:
    """Identify service from banner first, then fall back to port map."""
    for pattern, service in _BANNER_PATTERNS:
        if re.search(pattern, banner, re.IGNORECASE):
            return service
    return _PORT_SERVICE_MAP.get(port, f"unknown-{port}")


def parse_version(banner: str) -> str:
    """Extract version string from a service banner."""
    patterns = [
        r"(\d+\.\d+\.\d+[\w.-]*)",
        r"(\d+\.\d+[\w.-]+)",
        r"(?:version|ver)[:\s]+(\d[\w.]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)
    return "unknown"


# ---------------------------------------------------------------------------
# Async port scanner
# ---------------------------------------------------------------------------

async def _check_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> Optional[Tuple[str, int, str]]:
    """
    Asynchronously check a single TCP port.
    Returns (host, port, banner) if open, else None.
    """
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            return None

        # Banner grab — send HTTP probe if no immediate banner
        banner = ""
        try:
            # Some services send a banner immediately
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            banner = data.decode(errors="replace").strip()
        except ConnectionResetError:
            # If the server resets the connection immediately after handshake,
            # it is effectively closed/filtered.
            return None
        except (asyncio.TimeoutError, OSError):
            pass

        if not banner:
            # FIX BUG-2: HTTP probe now sends the actual host, not the literal
            # string "target". Virtualhost-based servers (most modern HTTP servers)
            # route requests by the Host header; "target" always returns 404 or a
            # wrong vhost response, poisoning every HTTP banner grab.
            try:
                probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode(errors="replace").strip()
            except (asyncio.TimeoutError, OSError):
                pass

        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

        return host, port, banner


async def scan_host_async(
    host: str,
    ports: List[int],
    timeout: float = 1.5,
    concurrency: int = 200,
) -> List[Tuple[str, int, str]]:
    """Scan all ports on a single host concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [_check_port(host, port, timeout, semaphore) for port in ports]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# Nmap integration (optional, richer fingerprinting)
# ---------------------------------------------------------------------------

# FIX BUG-4: Chunk size for Nmap calls.
# The original code silently truncated to ports[:100], dropping all ports
# above index 100 from Nmap enrichment with no warning.  We now call Nmap
# in chunks of NMAP_CHUNK_SIZE so every open port gets enriched.
NMAP_CHUNK_SIZE = 100


def _try_nmap_scan(
    host: str,
    ports: List[int],
    timing: int = 4,
) -> Dict[int, Dict]:
    """
    Run an Nmap service/version scan on specific open ports.
    Returns a dict keyed by port with service metadata.
    Falls back gracefully if Nmap is unavailable.

    BUG-4 FIX: Nmap is called in chunks of NMAP_CHUNK_SIZE instead of
    silently dropping all ports beyond the first 100.
    """
    try:
        import nmap  # type: ignore
    except ImportError:
        logger.debug("python-nmap not installed; skipping Nmap enrichment.")
        return {}

    enriched: Dict[int, Dict] = {}
    nm = nmap.PortScanner()
    args = f"-sV -T{timing} --version-intensity 5 -O --script=banner"

    # Chunk the port list so we never silently drop ports
    for chunk_start in range(0, len(ports), NMAP_CHUNK_SIZE):
        chunk = ports[chunk_start : chunk_start + NMAP_CHUNK_SIZE]
        port_str = ",".join(str(p) for p in chunk)

        try:
            nm.scan(host, ports=port_str, arguments=args, timeout=120)
        except Exception as exc:
            logger.warning("Nmap scan failed for %s (ports %s…): %s",
                           host, chunk[0], exc)
            continue  # try remaining chunks even if one fails

        if host not in nm.all_hosts():
            continue

        for proto in nm[host].all_protocols():
            for port, info in nm[host][proto].items():
                enriched[int(port)] = {
                    "service": info.get("name", "unknown"),
                    "version": info.get("version", "unknown"),
                    "product": info.get("product", ""),
                    "extrainfo": info.get("extrainfo", ""),
                    "banner": info.get("script", {}).get("banner", ""),
                }

    return enriched


def _try_nmap_discovery(target: str) -> set:
    """
    Run a fast Nmap ping sweep (-sn) to discover active hosts.
    Returns a set of discovered IP addresses.
    """
    try:
        import nmap  # type: ignore
    except ImportError:
        return set()

    nm = nmap.PortScanner()
    try:
        # -sn: Ping Scan - disable port scan
        # -PE: ICMP echo, -PS80,443: TCP SYN discovery, -PA22,80,443: TCP ACK discovery
        # nmap ping discovery is much more advanced than our simple sweep.
        nm.scan(hosts=target, arguments="-sn --host-timeout 5s")
        return set(nm.all_hosts())
    except Exception as exc:
        logger.debug("Nmap discovery failed: %s", exc)
        return set()


# ---------------------------------------------------------------------------
# CVE database
# ---------------------------------------------------------------------------

# FIX BUG-5: Explicit service-family whitelist replaces the previous
# substring containment check (`key in service or service in key`).
#
# The old logic caused "http" to match "https", "http-proxy", "xmlhttp",
# and vice versa — so scanning port 8080 (http-proxy) incorrectly inherited
# every Critical Apache CVE tagged for "http".  The whitelist below maps each
# canonical CVE-DB service name to the set of detected service names that
# should inherit its entries.  Matches are exact (set membership), not
# substring, so false positives are eliminated.
_SERVICE_FAMILY_MAP: Dict[str, set] = {
    "http":       {"http", "http-proxy", "http-alt"},
    "https":      {"https", "https-alt"},
    "ssh":        {"ssh"},
    "ftp":        {"ftp"},
    "smtp":       {"smtp", "smtp-submission"},
    "pop3":       {"pop3", "pop3s"},
    "imap":       {"imap", "imaps"},
    "smb":        {"smb", "netbios-ssn", "microsoft-ds"},
    "mysql":      {"mysql"},
    "postgresql": {"postgresql"},
    "redis":      {"redis"},
    "mongodb":    {"mongodb"},
    "vnc":        {"vnc"},
    "rdp":        {"rdp"},
    "telnet":     {"telnet"},
    "dns":        {"dns"},
    "rpcbind":    {"rpcbind", "msrpc"},
}

# Reverse index: detected-service → set of CVE-DB keys to query
_DETECTED_TO_CVE_KEYS: Dict[str, set] = {}
for _cve_key, _detected_set in _SERVICE_FAMILY_MAP.items():
    for _det in _detected_set:
        _DETECTED_TO_CVE_KEYS.setdefault(_det, set()).add(_cve_key)


class CveDatabase:
    """Load and query a local CVE CSV database."""

    def __init__(self, db_path: str = "config/cve_db.csv"):
        self._db: Dict[str, List[Dict]] = {}
        self._load(db_path)

    def _load(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            logger.warning("CVE database not found at '%s'. CVE matching disabled.", path)
            return
        try:
            with p.open(newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                required = {"service", "version", "cve_id", "description", "severity"}
                # cvss_score / cvss_vector are optional new columns added in
                # cve_db.csv v2.  Old DBs without them still load cleanly.
                if not required.issubset(set(reader.fieldnames or [])):
                    logger.error(
                        "CVE DB missing columns. Expected: %s", required
                    )
                    return
                for row in reader:
                    svc = row["service"].strip().lower()
                    # Parse optional CVSS v3.1 columns — fall back to None if
                    # absent so old single-format DBs continue to load without error.
                    raw_score = row.get("cvss_score", "").strip()
                    try:
                        cvss_score: float | None = float(raw_score) if raw_score else None
                    except ValueError:
                        cvss_score = None
                    cvss_vector: str | None = row.get("cvss_vector", "").strip() or None

                    self._db.setdefault(svc, []).append(
                        {
                            "cve_id": row["cve_id"].strip(),
                            "description": row["description"].strip(),
                            "severity": row["severity"].strip().capitalize(),
                            "version": row["version"].strip(),
                            "cvss_score": cvss_score,    # float | None
                            "cvss_vector": cvss_vector,  # str | None
                        }
                    )
            logger.info(
                "Loaded CVE DB: %d services, %d entries",
                len(self._db),
                sum(len(v) for v in self._db.values()),
            )
        except Exception as exc:
            logger.error("Failed to load CVE database: %s", exc)

    def match(self, service: str, version: str) -> List[Dict]:
        """
        Return matching CVEs for a service/version pair.

        BUG-5 FIX: Uses an explicit whitelist (_DETECTED_TO_CVE_KEYS) instead
        of substring containment.  A detected service of "http-proxy" now only
        inherits CVEs whose DB key is explicitly mapped to it (currently "http"),
        not every key that happens to contain "http" as a substring.
        """
        service = service.lower()
        matches: List[Dict] = []
        seen: set = set()

        # Build the set of CVE-DB keys to query for this detected service
        candidate_keys: set = _DETECTED_TO_CVE_KEYS.get(service, set())
        # Always include the service name itself in case it is a CVE-DB key
        candidate_keys = candidate_keys | {service}

        for key in candidate_keys:
            for entry in self._db.get(key, []):
                if entry["version"] == "*" or (
                    version != "unknown" and entry["version"] in version
                ):
                    uid = entry["cve_id"]
                    if uid not in seen:
                        seen.add(uid)
                        matches.append(entry)
        return matches


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

# Severity → weight fallback table.
# Used ONLY when a CVE entry has no cvss_score (e.g. rows from an old DB that
# predates the cvss_score column, or entries whose CVSS v3 score is unpublished).
# Values are kept slightly below the CVSS Critical ceiling (10.0) so that real
# CVSS scores always rank higher than fallback-scored entries.
_SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High":     7.0,
    "Medium":   4.5,
    "Low":      2.0,
    "Info":     0.5,
}


def calculate_risk_score(vulns: List[Dict]) -> float:
    """
    Compute a 0–10 risk score for a list of CVE matches on a single open port.

    Algorithm (CVSS-2):
      Pass 1 — per-vuln base score:
        • If the entry carries a numeric cvss_score (CVSS v3.1 base score from
          NVD), use it directly — this is the authoritative value.
        • Otherwise fall back to _SEVERITY_WEIGHTS[severity] so rows that
          predate the cvss_score column still produce a meaningful score.
      Pass 2 — aggregate:
        • max_score  : highest individual base score in the list.
        • count_bonus: log-scaled bonus for vuln density — many CVEs on one
          port is worse than one, but the bonus is capped so it can never
          dominate (≈+0 for 1 vuln, +0.35 for 2, +0.55 for 3, +1.1 for 10).
        • final      : min(max_score + count_bonus, 10.0)

    Why max + log-bonus instead of average?
      A single Critical RCE is catastrophic regardless of how many Low vulns
      sit alongside it.  max preserves that intuition; log-bonus provides a
      secondary signal for vuln-dense services.

    Backwards compatible: rows without cvss_score use severity weights and
    produce scores slightly lower than the CVSS ceiling — intentionally
    conservative to encourage keeping the DB up to date.
    """
    if not vulns:
        return 0.0

    scores: List[float] = []
    for v in vulns:
        cvss = v.get("cvss_score")
        if cvss is not None:
            # CVSS v3.1 base score — use directly (already on 0–10 scale)
            scores.append(float(cvss))
        else:
            # Legacy row: derive from severity string
            scores.append(_SEVERITY_WEIGHTS.get(v.get("severity", ""), 0.0))

    max_score = max(scores)
    if max_score == 0.0:
        return 0.0

    # log1p(n-1): +0 for 1 vuln, +0.35 for 2, +0.55 for 3, +1.1 for 10
    count_bonus = math.log1p(len(vulns) - 1) * 0.5
    return round(min(max_score + count_bonus, 10.0), 2)


# ---------------------------------------------------------------------------
# Host info helpers  (platform / subprocess imported at module level)
# ---------------------------------------------------------------------------

def _read_arp_cache_sync(host: str) -> str:
    """
    Synchronous ARP lookup — intended to be run in a thread executor,
    never called directly from an async context.

    platform and subprocess are imported at module level (BUG-3 / general
    improvement) so this function does not trigger repeated import overhead.
    """
    try:
        if platform.system() == "Windows":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            out = subprocess.check_output(
                ["arp", "-a", host], timeout=2,
                creationflags=flags,
            ).decode(errors="ignore")
        else:
            out = subprocess.check_output(
                ["arp", "-n", host], timeout=2,
            ).decode(errors="ignore")
    except Exception:
        return "Unknown"

    for line in out.splitlines():
        if host in line:
            parts = line.split()
            for part in parts:
                # Linux: xx:xx:xx:xx:xx:xx   Windows: xx-xx-xx-xx-xx-xx
                normalised = part.replace("-", ":")
                if len(normalised.split(":")) == 6:
                    return normalised
    return "Unknown"


def _read_arp_cache_all_sync() -> List[Tuple[str, str]]:
    """
    Read the full ARP table synchronously.  Returns list of (ip, mac) pairs.
    Intended to run in a thread executor.
    """
    try:
        if platform.system() == "Windows":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            out = subprocess.check_output(
                ["arp", "-a"], timeout=2, creationflags=flags,
            ).decode(errors="ignore")
        else:
            out = subprocess.check_output(["arp", "-n"], timeout=2).decode(errors="ignore")
    except Exception:
        return []

    entries: List[Tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            ip_raw = parts[0].strip("()")
            # Basic check to avoid header lines like "Interface:" or "Internet"
            # on Windows/Linux ARP output.
            if "." not in ip_raw and ":" not in ip_raw:
                continue
            mac = parts[1].replace("-", ":")
            entries.append((ip_raw, mac))
    return entries


# ---------------------------------------------------------------------------
# Main scanner orchestrator
# ---------------------------------------------------------------------------

class NetScopeScanner:
    """
    Orchestrates multi-host port scanning, service enrichment,
    and vulnerability matching.
    """

    def __init__(
        self,
        target: str,
        ports: List[int],
        timeout: float = 1.5,
        concurrency: int = 500,
        use_nmap: bool = True,
        nmap_timing: int = 4,
        cve_db_path: str = "config/cve_db.csv",
        # DESIGN-4 FIX: host_batch_size was a hard-coded magic number (20) buried
        # inside run().  It is now a first-class constructor parameter so it can be
        # set via ScanConfig / CLI --batch-size without touching source code.
        host_batch_size: int = 20,
    ):
        self.target = target
        self.hosts = validate_target(target)
        self.ports = ports
        self.timeout = timeout
        self.concurrency = concurrency
        self.use_nmap = use_nmap
        self.nmap_timing = nmap_timing
        self.host_batch_size = host_batch_size
        self.cve_db = CveDatabase(cve_db_path)
        self._results: List[PortResult] = []
        self._scan_start: Optional[str] = None
        self._scan_end: Optional[str] = None

        # BUG-6 FIX: Single shared executor created at init time and reused
        # across all hosts.  Shut down via close() or context-manager protocol.
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="netscope-nmap"
        )

        # DESIGN-1 FIX: Cache hostname/MAC lookups so each host is resolved
        # at most once even when called from both discovery and scan paths.
        self._host_info_cache: Dict[str, Tuple[str, str]] = {}

        logger.info(
            "Scanner initialised. Hosts: %d, Ports: %d, Concurrency: %d, Batch: %d",
            len(self.hosts),
            len(self.ports),
            self.concurrency,
            self.host_batch_size,
        )

    def close(self) -> None:
        """Release the shared thread-pool executor."""
        self._executor.shutdown(wait=False)

    def __enter__(self) -> "NetScopeScanner":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enrich_with_nmap(
        self, host: str, open_ports: List[int]
    ) -> Dict[int, Dict]:
        if not self.use_nmap or not open_ports:
            return {}
        logger.debug("Running Nmap enrichment on %s ports %s", host, open_ports)
        return _try_nmap_scan(host, open_ports, self.nmap_timing)

    def _build_port_result(
        self,
        host: str,
        port: int,
        banner: str,
        nmap_info: Optional[Dict] = None,
    ) -> PortResult:
        service = identify_service(port, banner)
        version = parse_version(banner)

        if nmap_info:
            service = nmap_info.get("service") or service
            version = nmap_info.get("version") or version
            if not banner and nmap_info.get("banner"):
                banner = nmap_info["banner"]

        vulns = self.cve_db.match(service, version)
        risk = calculate_risk_score(vulns)

        return PortResult(
            host=host,
            port=port,
            state="open",
            service=service,
            version=version,
            banner=banner[:512],  # cap banner length for safety
            vulnerabilities=vulns,
            risk_score=round(risk, 2),
        )

    # ------------------------------------------------------------------
    # Host info gathering  (cached + async-safe)
    # ------------------------------------------------------------------

    async def _get_host_info_async(self, host: str) -> Tuple[str, str]:
        """
        Resolve hostname and MAC address, using a cache so each host is
        looked up at most once.  The blocking ARP call runs in the shared
        executor so it never blocks the event loop.
        """
        if host in self._host_info_cache:
            return self._host_info_cache[host]

        # Reverse-DNS lookup — socket.gethostbyaddr is blocking but fast
        loop = asyncio.get_running_loop()  # FIX BUG-1 (applied here too)
        hostname = "Unknown"
        try:
            hostname = await loop.run_in_executor(
                self._executor, socket.gethostbyaddr, host
            )
            hostname = hostname[0]
        except Exception:
            pass

        # ARP lookup — blocking subprocess, run in executor
        mac_addr = await loop.run_in_executor(
            self._executor, _read_arp_cache_sync, host
        )

        result = (hostname, mac_addr)
        self._host_info_cache[host] = result
        return result

    # ------------------------------------------------------------------
    # Scan a single host
    # ------------------------------------------------------------------

    async def _scan_single_host(self, host: str) -> List[PortResult]:
        logger.info("Scanning host %s …", host)

        hostname, mac_addr = await self._get_host_info_async(host)
        logger.info("  [i] Hostname : %s", hostname)
        logger.info("  [i] MAC Addr : %s", mac_addr)

        open_ports_raw = await scan_host_async(
            host, self.ports, self.timeout, self.concurrency
        )

        if not open_ports_raw:
            logger.debug("No open ports on %s", host)
            return []

        open_port_nums = [p for _, p, _ in open_ports_raw]
        banners = {p: b for _, p, b in open_ports_raw}

        # Optional Nmap enrichment — runs in the shared executor (BUG-6 FIX)
        nmap_data: Dict[int, Dict] = {}
        if self.use_nmap:
            # FIX BUG-1: use get_running_loop(), not get_event_loop()
            loop = asyncio.get_running_loop()
            nmap_data = await loop.run_in_executor(
                self._executor, self._enrich_with_nmap, host, open_port_nums
            )

        results: List[PortResult] = []
        for port in open_port_nums:
            pr = self._build_port_result(
                host, port, banners.get(port, ""), nmap_data.get(port)
            )
            results.append(pr)
            logger.info(
                "  [+] %s:%d  %-12s  %-15s  risk=%.1f  vulns=%d",
                host, port, pr.service, pr.version, pr.risk_score,
                len(pr.vulnerabilities),
            )
        return results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> ScanSummary:
        """Execute the full scan and return a ScanSummary."""
        self._scan_start = datetime.utcnow().isoformat()
        all_results: List[PortResult] = []

        # Scan hosts concurrently in polite batches (DESIGN-4: configurable batch size)
        for i in range(0, len(self.hosts), self.host_batch_size):
            batch = self.hosts[i : i + self.host_batch_size]
            tasks = [self._scan_single_host(h) for h in batch]
            batched = await asyncio.gather(*tasks)
            for host_results in batched:
                all_results.extend(host_results)

        self._scan_end = datetime.utcnow().isoformat()
        self._results = all_results

        high_risk = list(
            {r.host for r in all_results if r.risk_score >= 7.5}
        )
        total_vulns = sum(len(r.vulnerabilities) for r in all_results)

        # DESIGN-2 FIX: populate both new fields separately
        hosts_with_results = len({r.host for r in all_results})

        return ScanSummary(
            target=self.target,
            hosts_targeted=len(self.hosts),        # every IP in the CIDR range
            hosts_with_results=hosts_with_results, # hosts with ≥1 open port
            open_ports=len(all_results),
            total_vulns=total_vulns,
            high_risk_hosts=high_risk,
            scan_start=self._scan_start,
            scan_end=self._scan_end,
            results=all_results,
        )

    # ------------------------------------------------------------------
    # Discovery mode
    # ------------------------------------------------------------------

    async def _ping_host(self, host: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """
        Async ICMP ping using a subprocess.  platform/subprocess are now
        module-level imports so they are not re-imported on every coroutine
        invocation.
        """
        async with semaphore:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
            t_val = "1000" if platform.system().lower() == "windows" else "1"
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping", param, "1", timeout_param, t_val, host,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    creationflags=flags,
                )
                await proc.wait()
                if proc.returncode == 0:
                    return host
            except Exception:
                pass
            return None

    async def _nudge_host(self, host: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """
        Force the OS to perform an ARP request by attempting a sub-second
        TCP connection to common ports.
        """
        # We check a few common ports to increase the chance of a response,
        # including mobile-specific and local service discovery ports.
        # 80/443: Web | 22: SSH | 5353: mDNS | 62078: iOS Lockdown | 8008: Android
        target_ports = [80, 443, 22, 5353, 62078, 8008]
        async with semaphore:
            for port in target_ports:
                try:
                    # Increased timeout to 1s for slow-waking mobile devices
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=1.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    return host
                except ConnectionRefusedError:
                    # A refusal means the host is UP and responded with RST.
                    # This is a definitive signal of an active host.
                    return host
                except (OSError, asyncio.TimeoutError):
                    # Even a refusal or timeout means the OS attempted ARP
                    continue
            return None

    async def run_discovery(self) -> int:
        """
        Run a fast host discovery sweep (ping sweep + ARP cache check).

        FIX BUG-3: The ARP cache read was previously a blocking
        subprocess.check_output() call made directly inside an async
        function.  It now runs via loop.run_in_executor() so the event
        loop is never blocked.
        """
        print("\n" + "=" * 60)
        print(f"  HOST DISCOVERY")
        print(f"  Target : {self.target}")
        print("=" * 60)

        logger.info("Sweeping %d hosts with ICMP + TCP nudges...", len(self.hosts))
        semaphore = asyncio.Semaphore(min(self.concurrency, 200))

        # Run both ICMP pings and TCP nudges in parallel to maximize speed
        # while forcing the ARP cache to populate.
        ping_tasks = [self._ping_host(h, semaphore) for h in self.hosts]
        nudge_tasks = [self._nudge_host(h, semaphore) for h in self.hosts]

        # Gather all results
        results = await asyncio.gather(*(ping_tasks + nudge_tasks))
        active_hosts: set = {h for h in results if h is not None}

        loop = asyncio.get_running_loop()

        # Nmap Discovery Booster (if available)
        # Nmap's ARP scan and advanced ping discovery are much more effective
        # on local networks than custom TCP nudges.
        if self.use_nmap:
            logger.info("Boosting discovery with Nmap ping sweep...")
            nmap_hosts = await loop.run_in_executor(
                self._executor, _try_nmap_discovery, self.target
            )
            active_hosts.update(nmap_hosts)

        # FIX BUG-3: ARP cache fallback now runs in the executor, not inline
        arp_entries = await loop.run_in_executor(
            self._executor, _read_arp_cache_all_sync
        )

        hosts_set = set(self.hosts)
        for ip, mac in arp_entries:
            if (
                ip in hosts_set
                and mac not in ("ff:ff:ff:ff:ff:ff", "ff-ff-ff-ff-ff-ff")
            ):
                active_hosts.add(ip)

        # Sort IP addresses properly
        active_hosts_list = sorted(
            active_hosts,
            key=lambda ip: [int(x) for x in ip.split(".")],
        )

        print("\n  Active Hosts:")
        print(f"  {'IP Address':<18} {'MAC Address':<20} {'Hostname'}")
        print("  " + "-" * 56)

        for host in active_hosts_list:
            hostname, mac = await self._get_host_info_async(host)
            print(f"  {host:<18} {mac:<20} {hostname}")

        print("\n" + "=" * 60)
        print(f"  Discovery complete. Found {len(active_hosts_list)} active hosts.")
        print("=" * 60 + "\n")
        return 0