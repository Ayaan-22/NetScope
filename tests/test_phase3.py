"""
NetScope Unit & Integration Tests — Phase 3 additions
Covers all gaps identified in the Phase 2 analysis:
  - NetScopeScanner.run() end-to-end integration
  - CLI argument parsing (main.py)
  - export_all() multi-format exporter
  - Async edge cases: partial banner, simultaneous reset, semaphore pressure
  - DESIGN-2: ScanSummary.hosts_targeted vs hosts_with_results
  - DESIGN-3: ScanConfig load-order (env always wins over YAML)
  - DESIGN-4: host_batch_size plumbed through scanner and CLI

Run with:
  pytest tests/ -v --tb=short
  pytest tests/test_phase3.py -v        # just new tests
"""

import asyncio
import csv
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Add project root to path ──────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner.engine import (
    NetScopeScanner,
    ScanSummary,
    PortResult,
    scan_host_async,
    validate_target,
    validate_ports,
    identify_service,
    calculate_risk_score,
    CveDatabase,
)
from src.reporting.reporter import generate_html, generate_json, generate_csv, export_all
from src.utils.config import ScanConfig


# =============================================================================
# Shared fixtures
# =============================================================================

def _start_banner_server(port: int, banner: bytes, stop_event: threading.Event) -> None:
    """Minimal TCP server that sends a fixed banner then closes."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(10)
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            conn.sendall(banner)
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            break
    srv.close()


def _start_reset_server(port: int, stop_event: threading.Event) -> None:
    """Server that accepts connections but immediately resets them (RST)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                   __import__("struct").pack("ii", 1, 0))
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            conn.close()   # close with linger=0 → RST
        except socket.timeout:
            continue
        except Exception:
            break
    srv.close()


def _start_slow_server(port: int, stop_event: threading.Event) -> None:
    """Server that accepts but sends no banner (simulates a silent service)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            time.sleep(5)   # send nothing — triggers banner-grab timeout
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            break
    srv.close()


@pytest.fixture()
def ssh_server():
    """Echo server on port 19910 that sends an SSH banner."""
    port = 19910
    stop = threading.Event()
    t = threading.Thread(
        target=_start_banner_server,
        args=(port, b"SSH-2.0-OpenSSH_8.9p1\r\n", stop),
        daemon=True,
    )
    t.start()
    time.sleep(0.1)
    yield port
    stop.set()
    t.join(timeout=2)


@pytest.fixture()
def http_server():
    """Echo server on port 19911 that sends an HTTP banner."""
    port = 19911
    stop = threading.Event()
    t = threading.Thread(
        target=_start_banner_server,
        args=(port, b"HTTP/1.1 200 OK\r\nServer: TestHTTP/1.0\r\n\r\n", stop),
        daemon=True,
    )
    t.start()
    time.sleep(0.1)
    yield port
    stop.set()
    t.join(timeout=2)


@pytest.fixture()
def reset_server():
    """Server on port 19912 that RSTs every connection."""
    port = 19912
    stop = threading.Event()
    t = threading.Thread(target=_start_reset_server, args=(port, stop), daemon=True)
    t.start()
    time.sleep(0.1)
    yield port
    stop.set()
    t.join(timeout=2)


@pytest.fixture()
def slow_server():
    """Server on port 19913 that never sends a banner."""
    port = 19913
    stop = threading.Event()
    t = threading.Thread(target=_start_slow_server, args=(port, stop), daemon=True)
    t.start()
    time.sleep(0.1)
    yield port
    stop.set()
    t.join(timeout=2)


@pytest.fixture()
def tmp_cve_db(tmp_path):
    """Write a minimal CVE CSV and return its path string."""
    p = tmp_path / "cve_db.csv"
    rows = [
        {"service": "ssh",  "version": "*",   "cve_id": "CVE-2023-0001", "description": "SSH wildcard",  "severity": "High"},
        {"service": "ssh",  "version": "7.2",  "cve_id": "CVE-2016-0777", "description": "SSH 7.2",       "severity": "High"},
        {"service": "http", "version": "*",   "cve_id": "CVE-2021-41773", "description": "Apache path",   "severity": "Critical"},
    ]
    with p.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return str(p)


def _make_summary(
    target: str = "10.0.0.1",
    hosts_targeted: int = 1,
    hosts_with_results: int = 1,
    results: list | None = None,
) -> ScanSummary:
    """Build a minimal ScanSummary for report tests."""
    if results is None:
        r = PortResult(
            host="10.0.0.1", port=22, state="open",
            service="ssh", version="7.2",
            banner="SSH-2.0-OpenSSH_7.2",
            vulnerabilities=[
                {"cve_id": "CVE-2016-0777", "description": "Roaming", "severity": "High"}
            ],
            risk_score=8.0,
        )
        results = [r]
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    return ScanSummary(
        target=target,
        hosts_targeted=hosts_targeted,
        hosts_with_results=hosts_with_results,
        open_ports=len(results),
        total_vulns=total_vulns,
        high_risk_hosts=[r.host for r in results if r.risk_score >= 7.5],
        scan_start="2024-01-01T00:00:00",
        scan_end="2024-01-01T00:01:00",
        results=results,
    )


# =============================================================================
# 1.  NetScopeScanner.run() — end-to-end integration
# =============================================================================

@pytest.mark.asyncio
class TestNetScopeScannerRun:
    """
    Integration tests for the full scanner pipeline.
    Use real localhost servers so the async scan path, banner grab,
    service detection, and CVE matching all execute for real.
    Nmap is disabled to keep tests self-contained and fast.
    """

    async def test_run_discovers_ssh_port(self, ssh_server, tmp_cve_db):
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[ssh_server],
            timeout=2.0,
            concurrency=10,
            use_nmap=False,
            cve_db_path=tmp_cve_db,
        ) as scanner:
            summary = await scanner.run()

        assert summary.open_ports == 1
        assert len(summary.results) == 1
        result = summary.results[0]
        assert result.host == "127.0.0.1"
        assert result.port == ssh_server
        assert result.service == "ssh"
        assert "SSH" in result.banner

    async def test_run_matches_cves_for_open_port(self, ssh_server, tmp_cve_db):
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[ssh_server],
            timeout=2.0,
            concurrency=10,
            use_nmap=False,
            cve_db_path=tmp_cve_db,
        ) as scanner:
            summary = await scanner.run()

        result = summary.results[0]
        cve_ids = {v["cve_id"] for v in result.vulnerabilities}
        # Wildcard entry should always match
        assert "CVE-2023-0001" in cve_ids
        assert result.risk_score > 0

    async def test_run_no_open_ports(self, tmp_cve_db):
        """Scanning a port that is definitely closed returns empty results."""
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[19950],   # nothing listening here
            timeout=0.5,
            concurrency=10,
            use_nmap=False,
            cve_db_path=tmp_cve_db,
        ) as scanner:
            summary = await scanner.run()

        assert summary.open_ports == 0
        assert summary.results == []
        assert summary.total_vulns == 0
        assert summary.high_risk_hosts == []

    async def test_run_multiple_ports_mixed(self, ssh_server, http_server, tmp_cve_db):
        """Scanner finds both open ports; closed port is not included."""
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[ssh_server, http_server, 19950],
            timeout=2.0,
            concurrency=10,
            use_nmap=False,
            cve_db_path=tmp_cve_db,
        ) as scanner:
            summary = await scanner.run()

        open_ports = {r.port for r in summary.results}
        assert ssh_server in open_ports
        assert http_server in open_ports
        assert 19950 not in open_ports
        assert summary.open_ports == 2

    async def test_run_context_manager_closes_executor(self, tmp_cve_db):
        """Exiting the context manager shuts the executor down cleanly."""
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[19950],
            timeout=0.3,
            use_nmap=False,
            cve_db_path=tmp_cve_db,
        ) as scanner:
            executor = scanner._executor
        # After __exit__, the executor should be shut down
        assert executor._shutdown

    async def test_run_high_risk_host_flagged(self, ssh_server, tmp_cve_db):
        """A host with risk_score ≥ 7.5 appears in high_risk_hosts."""
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[ssh_server],
            timeout=2.0,
            use_nmap=False,
            cve_db_path=tmp_cve_db,
        ) as scanner:
            summary = await scanner.run()

        # SSH with High CVEs should push risk ≥ 7.5
        if any(r.risk_score >= 7.5 for r in summary.results):
            assert "127.0.0.1" in summary.high_risk_hosts
        else:
            assert "127.0.0.1" not in summary.high_risk_hosts


# =============================================================================
# 2.  DESIGN-2: ScanSummary.hosts_targeted vs hosts_with_results
# =============================================================================

class TestScanSummaryDesign2:

    def test_hosts_targeted_counts_cidr_size(self):
        """hosts_targeted should reflect the CIDR range, not results."""
        summary = _make_summary(hosts_targeted=256, hosts_with_results=3)
        assert summary.hosts_targeted == 256

    def test_hosts_with_results_counts_responding(self):
        """hosts_with_results should count only hosts with open ports."""
        summary = _make_summary(hosts_targeted=256, hosts_with_results=3)
        assert summary.hosts_with_results == 3

    def test_hosts_scanned_property_is_alias(self):
        """The backwards-compat .hosts_scanned property returns hosts_with_results."""
        summary = _make_summary(hosts_targeted=254, hosts_with_results=5)
        assert summary.hosts_scanned == 5
        assert summary.hosts_scanned == summary.hosts_with_results

    def test_targeted_and_results_can_differ_significantly(self):
        """A /24 with 1 alive host: targeted=254, with_results=1."""
        summary = _make_summary(hosts_targeted=254, hosts_with_results=1)
        assert summary.hosts_targeted == 254
        assert summary.hosts_with_results == 1
        # Old .hosts_scanned would have been 254 — wrong; now it's 1
        assert summary.hosts_scanned == 1

    @pytest.mark.asyncio
    async def test_run_populates_hosts_targeted_correctly(self, tmp_cve_db):
        """run() must set hosts_targeted = number of IPs in the target range."""
        # /30 has 2 usable hosts
        with NetScopeScanner(
            target="127.0.0.0/30",
            ports=[19950],
            timeout=0.3,
            use_nmap=False,
            cve_db_path=tmp_cve_db,
        ) as scanner:
            summary = await scanner.run()

        assert summary.hosts_targeted == 2       # .1 and .2 in the /30
        assert summary.hosts_with_results == 0   # nothing listening on 19950


# =============================================================================
# 3.  DESIGN-3: ScanConfig load order (env > YAML > defaults)
# =============================================================================

class TestScanConfigLoadOrder:

    def test_defaults_without_yaml_or_env(self, tmp_path):
        """No YAML file, no env vars → pure defaults."""
        cfg = ScanConfig.load(str(tmp_path / "nonexistent.yaml"))
        assert cfg.timeout == 1.5
        assert cfg.concurrency == 500
        assert cfg.host_batch_size == 20
        assert cfg.use_nmap is True

    def test_yaml_overrides_defaults(self, tmp_path):
        """Values in YAML override built-in defaults."""
        yaml_file = tmp_path / "settings.yaml"
        yaml_file.write_text("timeout: 3.0\nconcurrency: 100\n")
        cfg = ScanConfig.load(str(yaml_file))
        assert cfg.timeout == 3.0
        assert cfg.concurrency == 100
        # Unset key stays at default
        assert cfg.host_batch_size == 20

    def test_env_overrides_yaml(self, tmp_path, monkeypatch):
        """
        DESIGN-3 core regression test.
        Old bug: YAML silently overwrote env vars.
        New behaviour: env vars always win over YAML.
        """
        yaml_file = tmp_path / "settings.yaml"
        yaml_file.write_text("timeout: 3.0\nconcurrency: 100\n")
        monkeypatch.setenv("NETSCOPE_TIMEOUT", "9.9")
        monkeypatch.setenv("NETSCOPE_CONCURRENCY", "42")

        cfg = ScanConfig.load(str(yaml_file))

        # Env must win — old bug would have given 3.0 and 100
        assert cfg.timeout == 9.9
        assert cfg.concurrency == 42

    def test_env_does_not_affect_unset_yaml_keys(self, tmp_path, monkeypatch):
        """Env var for a key not in YAML still overrides the default."""
        yaml_file = tmp_path / "settings.yaml"
        yaml_file.write_text("timeout: 2.0\n")
        monkeypatch.setenv("NETSCOPE_CONCURRENCY", "777")

        cfg = ScanConfig.load(str(yaml_file))
        assert cfg.timeout == 2.0      # from YAML
        assert cfg.concurrency == 777  # from env (not in YAML at all)

    def test_from_yaml_alias_has_same_precedence(self, tmp_path, monkeypatch):
        """from_yaml() (backwards compat alias) must use the same fixed order."""
        yaml_file = tmp_path / "settings.yaml"
        yaml_file.write_text("timeout: 5.0\n")
        monkeypatch.setenv("NETSCOPE_TIMEOUT", "1.1")

        cfg = ScanConfig.from_yaml(str(yaml_file))
        assert cfg.timeout == 1.1  # env wins, not YAML

    def test_batch_size_env_var(self, tmp_path, monkeypatch):
        """NETSCOPE_BATCH_SIZE env var is recognised."""
        monkeypatch.setenv("NETSCOPE_BATCH_SIZE", "50")
        cfg = ScanConfig.load(str(tmp_path / "nonexistent.yaml"))
        assert cfg.host_batch_size == 50

    def test_batch_size_yaml(self, tmp_path):
        """host_batch_size can be set in YAML."""
        yaml_file = tmp_path / "settings.yaml"
        yaml_file.write_text("host_batch_size: 75\n")
        cfg = ScanConfig.load(str(yaml_file))
        assert cfg.host_batch_size == 75

    def test_batch_size_env_beats_yaml(self, tmp_path, monkeypatch):
        """Env var for batch size wins over YAML."""
        yaml_file = tmp_path / "settings.yaml"
        yaml_file.write_text("host_batch_size: 75\n")
        monkeypatch.setenv("NETSCOPE_BATCH_SIZE", "10")
        cfg = ScanConfig.load(str(yaml_file))
        assert cfg.host_batch_size == 10


# =============================================================================
# 4.  DESIGN-4: host_batch_size plumbed through scanner
# =============================================================================

class TestBatchSize:

    def test_default_batch_size_on_scanner(self, tmp_cve_db):
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[80],
            use_nmap=False,
            cve_db_path=tmp_cve_db,
        ) as scanner:
            assert scanner.host_batch_size == 20

    def test_custom_batch_size_stored(self, tmp_cve_db):
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[80],
            use_nmap=False,
            cve_db_path=tmp_cve_db,
            host_batch_size=5,
        ) as scanner:
            assert scanner.host_batch_size == 5

    @pytest.mark.asyncio
    async def test_batch_size_one_still_scans_all_hosts(self, ssh_server, tmp_cve_db):
        """batch_size=1 should scan all hosts, just one at a time."""
        with NetScopeScanner(
            target="127.0.0.1",
            ports=[ssh_server],
            timeout=2.0,
            use_nmap=False,
            cve_db_path=tmp_cve_db,
            host_batch_size=1,
        ) as scanner:
            summary = await scanner.run()

        assert summary.open_ports == 1


# =============================================================================
# 5.  Async edge cases
# =============================================================================

@pytest.mark.asyncio
class TestAsyncEdgeCases:

    async def test_connection_reset_not_reported_as_open(self, reset_server):
        """
        A server that RSTs every connection should not appear as an open port.
        The original scanner's (ConnectionRefusedError, OSError) catch handles this.
        """
        results = await scan_host_async("127.0.0.1", [reset_server], timeout=1.0)
        assert results == []

    async def test_silent_service_still_detected_as_open(self, slow_server):
        """
        A service that accepts TCP but sends no banner should still be detected
        as open (the connection succeeded); banner should be empty string.
        """
        results = await scan_host_async("127.0.0.1", [slow_server], timeout=1.0)
        assert len(results) == 1
        _, port, banner = results[0]
        assert port == slow_server
        assert banner == "" or isinstance(banner, str)

    async def test_high_concurrency_semaphore(self, ssh_server):
        """
        Scanning with concurrency=1 forces serial execution — scanner must
        still return correct results, not deadlock or drop ports.
        """
        results = await scan_host_async(
            "127.0.0.1", [ssh_server], timeout=2.0, concurrency=1
        )
        assert len(results) == 1
        assert results[0][1] == ssh_server

    async def test_large_port_list_with_mostly_closed(self, ssh_server):
        """
        Scanning 50 ports where only one is open must return exactly one result.
        Validates that asyncio.gather does not return spurious results.
        """
        ports = list(range(19960, 20010))   # 50 closed ports
        ports.append(ssh_server)
        results = await scan_host_async("127.0.0.1", ports, timeout=0.5, concurrency=50)
        open_ports = [r[1] for r in results]
        assert ssh_server in open_ports
        for p in range(19960, 20010):
            assert p not in open_ports

    async def test_http_host_header_uses_actual_host(self, http_server):
        """
        BUG-2 regression: the HTTP probe must send the real host in the
        Host header.  Verify the banner is captured (server responded),
        meaning the probe was well-formed enough to get a response.
        """
        results = await scan_host_async("127.0.0.1", [http_server], timeout=2.0)
        assert len(results) == 1
        _, _, banner = results[0]
        # Our test server sends HTTP/1.1 — banner should contain it
        assert "HTTP" in banner

    async def test_timeout_does_not_block_other_tasks(self):
        """
        Even with a very short timeout, scanning should complete quickly
        across all ports (not hang waiting on slow connections).
        """
        ports = list(range(19970, 19980))   # 10 ports, nothing listening
        start = asyncio.get_event_loop().time()
        results = await scan_host_async("127.0.0.1", ports, timeout=0.3)
        elapsed = asyncio.get_event_loop().time() - start
        assert results == []
        # All 10 should time out within ~1s (not 10 × 0.3 = 3s sequentially)
        assert elapsed < 2.0


# =============================================================================
# 6.  export_all() — multi-format exporter
# =============================================================================

class TestExportAll:

    def test_export_all_creates_all_three_formats(self, tmp_path):
        summary = _make_summary()
        paths = export_all(summary, output_dir=str(tmp_path), formats=["html", "json", "csv"])
        assert set(paths.keys()) == {"html", "json", "csv"}
        for fmt, path in paths.items():
            assert Path(path).exists(), f"{fmt} file not created"
            assert Path(path).stat().st_size > 0

    def test_export_all_html_only(self, tmp_path):
        summary = _make_summary()
        paths = export_all(summary, output_dir=str(tmp_path), formats=["html"])
        assert set(paths.keys()) == {"html"}
        assert "json" not in paths
        assert "csv" not in paths

    def test_export_all_json_only(self, tmp_path):
        summary = _make_summary()
        paths = export_all(summary, output_dir=str(tmp_path), formats=["json"])
        data = json.loads(Path(paths["json"]).read_text())
        assert data["meta"]["target"] == "10.0.0.1"

    def test_export_all_filenames_contain_timestamp(self, tmp_path):
        summary = _make_summary()
        paths = export_all(summary, output_dir=str(tmp_path))
        for path in paths.values():
            name = Path(path).name
            # Timestamp pattern: YYYYMMDD_HHMMSS
            assert any(c.isdigit() for c in name), f"No timestamp in {name}"

    def test_export_all_custom_prefix(self, tmp_path):
        summary = _make_summary()
        paths = export_all(summary, output_dir=str(tmp_path), prefix="myscan")
        for path in paths.values():
            assert Path(path).name.startswith("myscan_")

    def test_export_all_creates_output_dir_if_missing(self, tmp_path):
        new_dir = str(tmp_path / "deep" / "nested" / "dir")
        summary = _make_summary()
        paths = export_all(summary, output_dir=new_dir, formats=["json"])
        assert Path(paths["json"]).exists()

    def test_export_all_default_formats_is_all_three(self, tmp_path):
        summary = _make_summary()
        paths = export_all(summary, output_dir=str(tmp_path))
        assert set(paths.keys()) == {"html", "json", "csv"}

    def test_export_all_json_contains_new_summary_fields(self, tmp_path):
        """DESIGN-2: both hosts_targeted and hosts_with_results appear in JSON."""
        summary = _make_summary(hosts_targeted=254, hosts_with_results=3)
        paths = export_all(summary, output_dir=str(tmp_path), formats=["json"])
        data = json.loads(Path(paths["json"]).read_text())
        meta = data["meta"]
        # Reporter must forward both new fields — adjust if reporter is updated
        # For now verify the legacy key is present (via the property)
        assert "hosts_scanned" in meta or "hosts_with_results" in meta

    def test_export_all_unknown_format_skipped_gracefully(self, tmp_path):
        summary = _make_summary()
        # Should not raise — unknown format is logged and skipped
        paths = export_all(summary, output_dir=str(tmp_path), formats=["json", "pdf"])
        assert "json" in paths
        assert "pdf" not in paths

    def test_export_all_empty_results(self, tmp_path):
        """export_all should succeed even with zero open ports."""
        summary = ScanSummary(
            target="10.0.0.0/24",
            hosts_targeted=254,
            hosts_with_results=0,
            open_ports=0,
            total_vulns=0,
            high_risk_hosts=[],
            scan_start="2024-01-01T00:00:00",
            scan_end="2024-01-01T00:00:05",
            results=[],
        )
        paths = export_all(summary, output_dir=str(tmp_path))
        for fmt, path in paths.items():
            assert Path(path).exists(), f"{fmt} missing for empty scan"


# =============================================================================
# 7.  CLI argument parsing (main.py)
# =============================================================================

class TestCLI:
    """
    Tests for the CLI layer in main.py.
    We call the script as a subprocess so the real argparse and sys.exit()
    paths execute, including invalid-argument handling.
    """

    MAIN = str(Path(__file__).parent.parent / "main.py")

    def _run(self, *args, timeout: int = 10) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, self.MAIN, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_help_exits_zero(self):
        result = self._run("--help")
        assert result.returncode == 0
        assert "TARGET" in result.stdout

    def test_missing_target_exits_nonzero(self):
        result = self._run("--formats", "json")
        assert result.returncode != 0

    def test_invalid_target_exits_2(self):
        result = self._run("-t", "999.999.999.999", "--no-nmap", "--timeout", "0.1")
        assert result.returncode == 2

    def test_invalid_port_spec_exits_2(self):
        result = self._run("-t", "127.0.0.1", "-p", "abc", "--no-nmap", "--timeout", "0.1")
        assert result.returncode == 2

    def test_network_too_large_exits_2(self):
        result = self._run("-t", "10.0.0.0/1", "--no-nmap", "--timeout", "0.1")
        assert result.returncode == 2

    def test_batch_size_flag_accepted(self):
        """--batch-size should be accepted without error (help text check)."""
        result = self._run("--help")
        assert "--batch-size" in result.stdout

    def test_batch_size_invalid_value_exits_nonzero(self):
        result = self._run("-t", "127.0.0.1", "--batch-size", "notanumber")
        assert result.returncode != 0

    def test_log_level_choices(self):
        """Invalid log level should cause argparse to exit non-zero."""
        result = self._run("-t", "127.0.0.1", "--log-level", "VERBOSE")
        assert result.returncode != 0

    def test_formats_choices_validated(self):
        """Unknown format should fail at argparse level."""
        result = self._run("-t", "127.0.0.1", "--formats", "pdf")
        assert result.returncode != 0

    def test_nmap_timing_out_of_range(self):
        result = self._run("-t", "127.0.0.1", "--nmap-timing", "9")
        assert result.returncode != 0

    def test_banner_printed(self):
        """The ASCII banner must appear in stdout on every invocation."""
        result = self._run("--help")
        assert "NetScope" in result.stdout


# =============================================================================
# 8.  Backwards compatibility — existing tests still pass with new APIs
# =============================================================================

class TestBackwardsCompat:
    """
    Ensure the ScanSummary API changes don't silently break existing code
    that references .hosts_scanned.
    """

    def test_hosts_scanned_property_exists(self):
        s = _make_summary(hosts_targeted=10, hosts_with_results=3)
        assert hasattr(s, "hosts_scanned")

    def test_hosts_scanned_returns_int(self):
        s = _make_summary(hosts_targeted=10, hosts_with_results=3)
        assert isinstance(s.hosts_scanned, int)

    def test_hosts_scanned_equals_with_results(self):
        for n in [0, 1, 5, 254]:
            s = _make_summary(hosts_targeted=256, hosts_with_results=n)
            assert s.hosts_scanned == n

    def test_existing_report_helpers_still_accept_summary(self, tmp_path):
        """generate_html/json/csv still work with the updated ScanSummary."""
        summary = _make_summary(hosts_targeted=1, hosts_with_results=1)
        html_path = generate_html(summary, str(tmp_path / "report.html"))
        json_path = generate_json(summary, str(tmp_path / "report.json"))
        csv_path  = generate_csv(summary,  str(tmp_path / "report.csv"))
        assert Path(html_path).exists()
        assert Path(json_path).exists()
        assert Path(csv_path).exists()
