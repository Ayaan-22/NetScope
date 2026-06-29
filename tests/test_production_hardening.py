import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import main
from src.reporting.differ import diff_reports
from src.reporting.reporter import generate_csv, generate_json
from src.scanner.engine import (
    CveDatabase,
    PortResult,
    ScanSummary,
    _hostname_from_netbios_output,
    _hostname_from_ping_output,
    _read_arp_cache_all_sync,
    _try_nmap_discovery,
    _try_nmap_scan,
    calculate_risk_score,
)


def _summary(results=None):
    results = results or []
    return ScanSummary(
        target="10.0.0.1",
        hosts_targeted=1,
        hosts_with_results=len({r.host for r in results}),
        open_ports=len(results),
        total_vulns=sum(len(r.vulnerabilities) for r in results),
        high_risk_hosts=[],
        scan_start="2026-01-01T00:00:00+00:00",
        scan_end="2026-01-01T00:00:01+00:00",
        results=results,
        metadata={"session_id": "test-session", "tool_version": "test"},
    )


def test_cvss_score_path_is_used():
    assert calculate_risk_score([{"severity": "Low", "cvss_score": 9.8}]) == 9.8


def test_cve_version_matching_uses_numeric_boundaries(tmp_path):
    db_path = tmp_path / "cve.csv"
    db_path.write_text(
        "service,version,cve_id,description,severity\n"
        "mysql,5.5,CVE-TEST-1,Boundary test,High\n",
        encoding="utf-8",
    )
    db = CveDatabase(str(db_path))
    assert db.match("mysql", "5.5.62")
    assert not db.match("mysql", "15.50")
    assert not db.match("mysql", "unknown")


def test_default_cve_db_loads_outside_repo_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    db = CveDatabase()

    assert db.match("ssh", "OpenSSH_7.2p2")


def test_nmap_os_detection_is_opt_in(monkeypatch):
    scanner = MagicMock()
    scanner.all_hosts.return_value = []
    port_scanner = MagicMock(return_value=scanner)
    fake_nmap = MagicMock(PortScanner=port_scanner)

    with patch.dict("sys.modules", {"nmap": fake_nmap}):
        _try_nmap_scan("127.0.0.1", [22], timing=3, os_detect=False)
        args = scanner.scan.call_args.kwargs["arguments"]
        assert "-O" not in args

        _try_nmap_scan("127.0.0.1", [22], timing=3, os_detect=True)
        args = scanner.scan.call_args.kwargs["arguments"]
        assert "-O" in args


def test_nmap_discovery_timeout_is_forwarded():
    scanner = MagicMock()
    scanner.all_hosts.return_value = ["127.0.0.1"]
    port_scanner = MagicMock(return_value=scanner)
    fake_nmap = MagicMock(PortScanner=port_scanner)

    with patch.dict("sys.modules", {"nmap": fake_nmap}):
        assert _try_nmap_discovery("127.0.0.1", timeout=7) == {"127.0.0.1"}
        assert scanner.scan.call_args.kwargs["timeout"] == 7


def test_linux_arp_table_parsing_uses_mac_column(monkeypatch):
    sample = (
        "Address HWtype HWaddress Flags Mask Iface\n"
        "192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0\n"
    )
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr("subprocess.check_output", lambda *_, **__: sample.encode())
    assert _read_arp_cache_all_sync() == [("192.168.1.1", "aa:bb:cc:dd:ee:ff")]


def test_windows_ping_output_extracts_hostname():
    output = "Pinging DESKTOP-T5D0DKR [10.100.105.12] with 32 bytes of data:"
    assert _hostname_from_ping_output(output, "10.100.105.12") == "DESKTOP-T5D0DKR"


def test_netbios_output_prefers_unique_workstation_name():
    output = """
           NetBIOS Remote Machine Name Table

       Name               Type         Status
    ---------------------------------------------
    WORKGROUP      <00>  GROUP       Registered
    DESKTOP-123    <00>  UNIQUE      Registered
    DESKTOP-123    <20>  UNIQUE      Registered
    """
    assert _hostname_from_netbios_output(output, "10.0.0.5") == "DESKTOP-123"


def test_json_and_csv_sanitize_untrusted_banners(tmp_path):
    result = PortResult(
        host="10.0.0.1",
        hostname="web-01",
        mac_address="aa:bb:cc:dd:ee:ff",
        port=80,
        service="http",
        banner="=CMD\x00\x1b",
    )
    summary = _summary([result])

    json_path = generate_json(summary, str(tmp_path / "report.json"))
    csv_path = generate_csv(summary, str(tmp_path / "report.csv"))

    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    assert data["results"][0]["banner"] == "=CMD"
    assert data["results"][0]["hostname"] == "web-01"
    assert data["results"][0]["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert "session_id" in data["meta"]

    csv_text = Path(csv_path).read_text(encoding="utf-8")
    assert "Hostname" in csv_text
    assert "MAC Address" in csv_text
    assert "web-01" in csv_text
    assert "'=CMD" in csv_text
    assert "\x00" not in csv_text


def test_diff_reports_detects_port_and_cve_changes(tmp_path):
    old = {
        "results": [
            {
                "host": "10.0.0.1",
                "port": 22,
                "service": "ssh",
                "risk_score": 4.0,
                "vulnerabilities": [],
            }
        ]
    }
    new = {
        "results": [
            {
                "host": "10.0.0.1",
                "port": 22,
                "service": "ssh",
                "risk_score": 8.0,
                "vulnerabilities": [{"cve_id": "CVE-NEW"}],
            },
            {
                "host": "10.0.0.1",
                "port": 443,
                "service": "https",
                "risk_score": 0.0,
                "vulnerabilities": [],
            },
        ]
    }
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(old), encoding="utf-8")
    new_path.write_text(json.dumps(new), encoding="utf-8")

    diff = diff_reports(str(old_path), str(new_path))
    assert diff.new_open_ports == [
        {"host": "10.0.0.1", "port": 443, "service": "https", "risk_score": 0.0}
    ]
    assert diff.new_vulnerabilities == [{"host": "10.0.0.1", "port": 22, "cve_id": "CVE-NEW"}]
    assert diff.risk_changes[0]["delta"] == 4.0


def test_public_targets_require_explicit_authorization():
    with pytest.raises(ValueError, match="Public targets require"):
        main.validate_scan_safety(
            ["8.8.8.8"],
            authorized_scan=False,
            allow_public_targets=False,
        )

    main.validate_scan_safety(
        ["8.8.8.8"],
        authorized_scan=True,
        allow_public_targets=True,
    )
