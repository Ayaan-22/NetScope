"""
NetScope Scanner Engine
Core scanning logic with async port scanning, service detection,
banner grabbing, and CVE matching.
"""

import asyncio
import socket
import re
import csv
import logging
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime
import concurrent.futures

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
    hosts_scanned: int
    open_ports: int
    total_vulns: int
    high_risk_hosts: List[str]
    scan_start: str
    scan_end: str
    results: List[PortResult]


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
                    "Limit scans to /16 or smaller."
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
        except asyncio.TimeoutError:
            pass

        if not banner:
            # HTTP probe
            try:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
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

def _try_nmap_scan(
    host: str,
    ports: List[int],
    timing: int = 4,
) -> Dict[int, Dict]:
    """
    Run an Nmap service/version scan on specific open ports.
    Returns a dict keyed by port with service metadata.
    Falls back gracefully if Nmap is unavailable.
    """
    try:
        import nmap  # type: ignore
    except ImportError:
        logger.debug("python-nmap not installed; skipping Nmap enrichment.")
        return {}

    nm = nmap.PortScanner()

    port_str = ",".join(str(p) for p in ports[:100])  # cap at 100 ports per call
    args = f"-sV -T{timing} --version-intensity 5 -O --script=banner"

    try:
        nm.scan(host, ports=port_str, arguments=args, timeout=120)
    except Exception as exc:
        logger.warning("Nmap scan failed for %s: %s", host, exc)
        return {}

    enriched: Dict[int, Dict] = {}
    if host not in nm.all_hosts():
        return enriched

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


# ---------------------------------------------------------------------------
# CVE database
# ---------------------------------------------------------------------------

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
                if not required.issubset(set(reader.fieldnames or [])):
                    logger.error(
                        "CVE DB missing columns. Expected: %s", required
                    )
                    return
                for row in reader:
                    svc = row["service"].strip().lower()
                    self._db.setdefault(svc, []).append(
                        {
                            "cve_id": row["cve_id"].strip(),
                            "description": row["description"].strip(),
                            "severity": row["severity"].strip().capitalize(),
                            "version": row["version"].strip(),
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
        """Return matching CVEs for a service/version pair."""
        service = service.lower()
        matches: List[Dict] = []
        seen: set = set()

        candidate_keys = {service}
        # Also match service family (e.g. "http" matches "http-proxy")
        for key in self._db:
            if key in service or service in key:
                candidate_keys.add(key)

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

_SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Info": 0.5,
}


def calculate_risk_score(vulns: List[Dict]) -> float:
    """
    Risk score 0–10 based on severity distribution.
    Formula: max_severity_weight + log-scaled count bonus, capped at 10.
    """
    if not vulns:
        return 0.0
    weights = [_SEVERITY_WEIGHTS.get(v.get("severity", ""), 0.0) for v in vulns]
    max_w = max(weights)
    import math
    count_bonus = math.log1p(len(vulns)) * 0.5
    return min(max_w + count_bonus, 10.0)


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
    ):
        self.target = target
        self.hosts = validate_target(target)
        self.ports = ports
        self.timeout = timeout
        self.concurrency = concurrency
        self.use_nmap = use_nmap
        self.nmap_timing = nmap_timing
        self.cve_db = CveDatabase(cve_db_path)
        self._results: List[PortResult] = []
        self._scan_start: Optional[str] = None
        self._scan_end: Optional[str] = None
        logger.info(
            "Scanner initialised. Hosts: %d, Ports: %d, Concurrency: %d",
            len(self.hosts),
            len(self.ports),
            self.concurrency,
        )

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
    # Host Info Gathering
    # ------------------------------------------------------------------

    def _get_host_info(self, host: str) -> Tuple[str, str]:
        """Attempt to resolve Hostname and MAC address natively."""
        import platform
        import subprocess
        
        hostname = "Unknown"
        mac_addr = "Unknown"
        
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except Exception:
            pass

        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(["arp", "-a", host], timeout=2, creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0).decode(errors="ignore")
                for line in out.splitlines():
                    if host in line:
                        parts = line.split()
                        if len(parts) >= 2 and "-" in parts[1]:
                            mac_addr = parts[1].replace("-", ":")
                            break
            else:
                out = subprocess.check_output(["arp", "-n", host], timeout=2).decode(errors="ignore")
                for line in out.splitlines():
                    if host in line:
                        parts = line.split()
                        for p in parts:
                            if ":" in p and len(p.split(":")) == 6:
                                mac_addr = p
                                break
        except Exception:
            pass
            
        return hostname, mac_addr

    # ------------------------------------------------------------------
    # Scan a single host
    # ------------------------------------------------------------------

    async def _scan_single_host(self, host: str) -> List[PortResult]:
        logger.info("Scanning host %s …", host)
        
        # Print Host Information
        hostname, mac_addr = self._get_host_info(host)
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

        # Optional Nmap enrichment (blocking — run in thread pool)
        nmap_data: Dict[int, Dict] = {}
        if self.use_nmap:
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                nmap_data = await loop.run_in_executor(
                    pool, self._enrich_with_nmap, host, open_port_nums
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

        # Scan hosts concurrently (but not all at once to be polite)
        batch_size = 20
        for i in range(0, len(self.hosts), batch_size):
            batch = self.hosts[i : i + batch_size]
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

        return ScanSummary(
            target=self.target,
            hosts_scanned=len(self.hosts),
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
        import platform
        import subprocess
        async with semaphore:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            t_val = '1000' if platform.system().lower() == 'windows' else '1'
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    'ping', param, '1', timeout_param, t_val, host,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                await proc.wait()
                if proc.returncode == 0:
                    return host
            except Exception:
                pass
            return None

    async def run_discovery(self) -> int:
        """Run a fast host discovery sweep (ping sweep + ARP check)."""
        print("\n" + "=" * 60)
        print(f"  HOST DISCOVERY")
        print(f"  Target : {self.target}")
        print("=" * 60)
        
        logger.info("Sweeping %d hosts...", len(self.hosts))
        semaphore = asyncio.Semaphore(min(self.concurrency, 100))
        tasks = [self._ping_host(h, semaphore) for h in self.hosts]
        
        results = await asyncio.gather(*tasks)
        active_hosts = set(h for h in results if h is not None)
        
        # Fallback: Check ARP cache for stealthy devices (like phones) that drop ICMP
        import platform
        import subprocess
        try:
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["arp", "-a"], 
                    timeout=2, 
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                ).decode(errors="ignore")
            else:
                out = subprocess.check_output(["arp", "-n"], timeout=2).decode(errors="ignore")
                
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip("()")
                    mac = parts[1]
                    # Ignore broadcast IP and multicast MACs
                    if ip in self.hosts and mac != "ff-ff-ff-ff-ff-ff" and mac != "ff:ff:ff:ff:ff:ff":
                        active_hosts.add(ip)
        except Exception:
            pass

        # Sort IP addresses properly
        active_hosts_list = sorted(list(active_hosts), key=lambda ip: [int(x) for x in ip.split('.')])
        
        print("\n  Active Hosts:")
        print(f"  {'IP Address':<18} {'MAC Address':<20} {'Hostname'}")
        print("  " + "-" * 56)
        
        for host in active_hosts_list:
            hostname, mac = self._get_host_info(host)
            print(f"  {host:<18} {mac:<20} {hostname}")
            
        print("\n" + "=" * 60)
        print(f"  Discovery complete. Found {len(active_hosts_list)} active hosts.")
        print("=" * 60 + "\n")
        return 0
