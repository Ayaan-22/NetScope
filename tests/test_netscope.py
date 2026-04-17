"""
NetScope Unit & Integration Tests
Run with:  pytest tests/ -v
"""

import asyncio
import csv
import socket
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── Add project root to path ──────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner.engine import (
    validate_target,
    validate_ports,
    identify_service,
    parse_version,
    calculate_risk_score,
    CveDatabase,
    NetScopeScanner,
    scan_host_async,
)
from src.reporting.reporter import generate_html, generate_json, generate_csv
from src.scanner.engine import ScanSummary, PortResult


# =============================================================================
# validate_target
# =============================================================================

class TestValidateTarget:
    def test_single_ip(self):
        assert validate_target("192.168.1.1") == ["192.168.1.1"]

    def test_cidr_slash32(self):
        hosts = validate_target("10.0.0.1/32")
        assert hosts == ["10.0.0.1"]

    def test_cidr_slash30(self):
        hosts = validate_target("192.168.1.0/30")
        # /30 has 2 usable hosts: .1 and .2
        assert len(hosts) == 2
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts

    def test_too_large_network(self):
        with pytest.raises(ValueError, match="65536"):
            validate_target("10.0.0.0/1")

    def test_invalid_ip(self):
        with pytest.raises(ValueError):
            validate_target("999.999.999.999")

    def test_empty_target(self):
        with pytest.raises(ValueError, match="empty"):
            validate_target("")

    def test_invalid_cidr(self):
        with pytest.raises(ValueError):
            validate_target("192.168.1.0/33")


# =============================================================================
# validate_ports
# =============================================================================

class TestValidatePorts:
    def test_single_port(self):
        assert validate_ports("80") == [80]

    def test_comma_list(self):
        assert validate_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        result = validate_ports("8080-8082")
        assert result == [8080, 8081, 8082]

    def test_mixed(self):
        result = validate_ports("22,80,8080-8082,443")
        assert result == [22, 80, 443, 8080, 8081, 8082]

    def test_deduplication(self):
        assert validate_ports("80,80,80") == [80]

    def test_invalid_port_zero(self):
        with pytest.raises(ValueError):
            validate_ports("0")

    def test_invalid_port_too_large(self):
        with pytest.raises(ValueError):
            validate_ports("99999")

    def test_invalid_text(self):
        with pytest.raises(ValueError):
            validate_ports("abc")

    def test_inverted_range(self):
        with pytest.raises(ValueError):
            validate_ports("443-80")


# =============================================================================
# identify_service
# =============================================================================

class TestIdentifyService:
    def test_ssh_banner(self):
        assert identify_service(9999, "SSH-2.0-OpenSSH_8.2") == "ssh"

    def test_http_banner(self):
        assert identify_service(9999, "HTTP/1.1 200 OK") == "http"

    def test_ftp_banner(self):
        assert identify_service(9999, "220 vsftpd FTP server ready") == "ftp"

    def test_port_fallback(self):
        assert identify_service(3306, "") == "mysql"
        assert identify_service(3389, "") == "rdp"

    def test_unknown_port_no_banner(self):
        svc = identify_service(12345, "")
        assert svc == "unknown-12345"


# =============================================================================
# parse_version
# =============================================================================

class TestParseVersion:
    def test_semver(self):
        assert parse_version("OpenSSH_8.2p1") == "8.2p1"

    def test_three_part(self):
        assert parse_version("Apache/2.4.51") == "2.4.51"

    def test_no_version(self):
        assert parse_version("garbled banner xyz") == "unknown"

    def test_version_keyword(self):
        assert parse_version("Server version: 5.7.32") == "5.7.32"


# =============================================================================
# calculate_risk_score
# =============================================================================

class TestCalculateRiskScore:
    def test_no_vulns(self):
        assert calculate_risk_score([]) == 0.0

    def test_single_critical(self):
        score = calculate_risk_score([{"severity": "Critical"}])
        assert score > 9.0  # 10 + small log bonus, capped at 10

    def test_single_low(self):
        score = calculate_risk_score([{"severity": "Low"}])
        assert score < 3.5

    def test_many_medium(self):
        vulns = [{"severity": "Medium"}] * 10
        score = calculate_risk_score(vulns)
        assert 5.0 <= score <= 10.0

    def test_score_capped_at_10(self):
        vulns = [{"severity": "Critical"}] * 100
        assert calculate_risk_score(vulns) <= 10.0

    def test_unknown_severity(self):
        score = calculate_risk_score([{"severity": "Nonexistent"}])
        assert score == 0.0  # unknown weight → 0


# =============================================================================
# CveDatabase
# =============================================================================

class TestCveDatabase:
    @pytest.fixture()
    def tmp_db(self, tmp_path):
        """Write a minimal CVE CSV and return its path."""
        p = tmp_path / "cve_db.csv"
        rows = [
            {"service": "ssh", "version": "*",    "cve_id": "CVE-2023-0001", "description": "SSH vuln",   "severity": "High"},
            {"service": "ssh", "version": "7.2",  "cve_id": "CVE-2016-0777", "description": "SSH 7.2",    "severity": "High"},
            {"service": "http","version": "*",    "cve_id": "CVE-2021-41773","description": "Apache path", "severity": "Critical"},
        ]
        with p.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return str(p)

    def test_wildcard_match(self, tmp_db):
        db = CveDatabase(tmp_db)
        matches = db.match("ssh", "8.9")
        ids = {m["cve_id"] for m in matches}
        assert "CVE-2023-0001" in ids

    def test_version_specific_match(self, tmp_db):
        db = CveDatabase(tmp_db)
        matches = db.match("ssh", "7.2")
        ids = {m["cve_id"] for m in matches}
        assert "CVE-2016-0777" in ids
        assert "CVE-2023-0001" in ids  # wildcard also matches

    def test_no_match(self, tmp_db):
        db = CveDatabase(tmp_db)
        matches = db.match("redis", "6.0")
        assert matches == []

    def test_missing_db(self, tmp_path):
        db = CveDatabase(str(tmp_path / "nonexistent.csv"))
        assert db.match("ssh", "8.0") == []

    def test_family_match(self, tmp_db):
        db = CveDatabase(tmp_db)
        # "http-proxy" should match entries for "http"
        matches = db.match("http-proxy", "2.4.51")
        ids = {m["cve_id"] for m in matches}
        assert "CVE-2021-41773" in ids


# =============================================================================
# Async port scanner — uses a real localhost echo server
# =============================================================================

def _start_echo_server(port: int, stop_event: threading.Event):
    """Minimal TCP server that accepts connections and sends a banner."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"SSH-2.0-OpenSSH_TestServer\r\n")
            conn.close()
        except socket.timeout:
            continue
    srv.close()


@pytest.mark.asyncio
class TestAsyncScanner:
    @pytest.fixture(autouse=True)
    def echo_server(self):
        """Start a local echo server on port 19922 for tests."""
        port = 19922
        stop = threading.Event()
        t = threading.Thread(target=_start_echo_server, args=(port, stop), daemon=True)
        t.start()
        time.sleep(0.1)
        yield port
        stop.set()
        t.join(timeout=2)

    async def test_open_port_detected(self, echo_server):
        results = await scan_host_async("127.0.0.1", [echo_server], timeout=2.0)
        assert len(results) == 1
        host, port, banner = results[0]
        assert host == "127.0.0.1"
        assert port == echo_server
        assert "SSH" in banner

    async def test_closed_port_not_reported(self):
        results = await scan_host_async("127.0.0.1", [19999], timeout=0.5)
        assert results == []

    async def test_multiple_ports(self, echo_server):
        results = await scan_host_async(
            "127.0.0.1", [echo_server, 19999, 19998], timeout=1.0
        )
        open_ports = [r[1] for r in results]
        assert echo_server in open_ports
        assert 19999 not in open_ports


# =============================================================================
# Report generation
# =============================================================================

def _make_summary() -> ScanSummary:
    r = PortResult(
        host="10.0.0.1", port=22, state="open",
        service="ssh", version="7.2", banner="SSH-2.0-OpenSSH_7.2",
        vulnerabilities=[
            {"cve_id": "CVE-2016-0777", "description": "Roaming disclosure", "severity": "High"}
        ],
        risk_score=8.0,
    )
    return ScanSummary(
        target="10.0.0.1", hosts_targeted=1, hosts_with_results=1,
        open_ports=1, total_vulns=1, high_risk_hosts=["10.0.0.1"],
        scan_start="2024-01-01T00:00:00", scan_end="2024-01-01T00:01:00",
        results=[r],
    )


class TestReports:
    def test_html_report(self, tmp_path):
        summary = _make_summary()
        out = str(tmp_path / "report.html")
        path = generate_html(summary, out)
        content = Path(path).read_text(encoding="utf-8")
        assert "10.0.0.1" in content
        assert "CVE-2016-0777" in content
        assert "<!DOCTYPE html>" in content

    def test_json_report(self, tmp_path):
        import json
        summary = _make_summary()
        out = str(tmp_path / "report.json")
        path = generate_json(summary, out)
        data = json.loads(Path(path).read_text())
        assert data["meta"]["target"] == "10.0.0.1"
        assert len(data["results"]) == 1
        assert data["results"][0]["port"] == 22

    def test_csv_report(self, tmp_path):
        summary = _make_summary()
        out = str(tmp_path / "report.csv")
        path = generate_csv(summary, out)
        rows = list(csv.DictReader(Path(path).open()))
        assert len(rows) == 1
        assert rows[0]["Host"] == "10.0.0.1"
        assert rows[0]["Port"] == "22"

    def test_html_xss_escaped(self, tmp_path):
        """Banner content must be HTML-escaped."""
        r = PortResult(
            host="10.0.0.1", port=80, state="open",
            service="http", version="unknown",
            banner='<script>alert("xss")</script>',
            vulnerabilities=[], risk_score=0.0,
        )
        summary = ScanSummary(
            target="10.0.0.1", hosts_targeted=1, hosts_with_results=1,
            open_ports=1, total_vulns=0, high_risk_hosts=[],
            scan_start="", scan_end="", results=[r],
        )
        out = str(tmp_path / "xss_test.html")
        content = Path(generate_html(summary, out)).read_text()
        assert "<script>" not in content
        assert "&lt;script&gt;" in content
