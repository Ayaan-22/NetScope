import json
from pathlib import Path

from fastapi.testclient import TestClient

from src.dashboard import app as dashboard_app
from src.dashboard.app import create_app
from src.reporting.reporter import generate_csv, generate_html, generate_json
from src.scanner.engine import PortResult, ScanSummary


def _summary() -> ScanSummary:
    result = PortResult(
        host="10.0.0.5",
        hostname="web-01",
        mac_address="aa:bb:cc:dd:ee:ff",
        port=443,
        service="https",
        version="2.4.49",
        banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.49",
        vulnerabilities=[
            {
                "cve_id": "CVE-2021-41773",
                "description": "Apache path traversal and RCE",
                "severity": "Critical",
                "cvss_score": 9.8,
            }
        ],
        risk_score=9.8,
    )
    return ScanSummary(
        target="10.0.0.0/24",
        hosts_targeted=254,
        hosts_with_results=1,
        open_ports=1,
        total_vulns=1,
        high_risk_hosts=["10.0.0.5"],
        scan_start="2026-01-01T00:00:00+00:00",
        scan_end="2026-01-01T00:00:03+00:00",
        results=[result],
        metadata={"session_id": "dash-test", "tool_version": "test"},
    )


def _write_report_bundle(tmp_path: Path, name: str = "netscope_dashboard_test") -> str:
    summary = _summary()
    generate_json(summary, str(tmp_path / f"{name}.json"))
    generate_html(summary, str(tmp_path / f"{name}.html"))
    generate_csv(summary, str(tmp_path / f"{name}.csv"))
    return name


def test_dashboard_health_and_defaults(tmp_path):
    client = TestClient(create_app(output_dir=str(tmp_path)))

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    defaults = client.get("/api/defaults")
    assert defaults.status_code == 200
    assert defaults.json()["output_dir"] == str(tmp_path)


def test_dashboard_local_network_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(
        dashboard_app,
        "detect_local_networks",
        lambda: [
            {
                "target": "192.168.10.0/24",
                "ip": "192.168.10.42",
                "netmask": "255.255.255.0",
                "prefix": 24,
                "adapter": "Wi-Fi",
                "gateway": "192.168.10.1",
                "source": "test",
                "capped": False,
                "usable_hosts": 254,
            }
        ],
    )
    client = TestClient(create_app(output_dir=str(tmp_path)))

    response = client.get("/api/local-networks")

    assert response.status_code == 200
    payload = response.json()
    assert payload["recommended"]["target"] == "192.168.10.0/24"
    assert payload["networks"][0]["adapter"] == "Wi-Fi"


def test_network_candidate_caps_overly_large_private_network():
    candidate = dashboard_app._network_candidate(
        "10.20.30.40",
        "255.0.0.0",
        adapter="Corp LAN",
        gateway="10.0.0.1",
    )

    assert candidate["target"] == "10.20.30.0/24"
    assert candidate["capped"] is True


def test_dashboard_lists_and_loads_reports(tmp_path):
    report_id = _write_report_bundle(tmp_path)
    client = TestClient(create_app(output_dir=str(tmp_path)))

    reports = client.get("/api/reports")
    assert reports.status_code == 200
    items = reports.json()
    assert items[0]["id"] == report_id
    assert items[0]["severity_counts"]["critical"] == 1
    assert items[0]["files"] == {"json": True, "html": True, "csv": True}

    detail = client.get(f"/api/reports/{report_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["analytics"]["cve_count"] == 1
    assert payload["analytics"]["risk_buckets"]["critical"] == 1
    assert payload["results"][0]["host"] == "10.0.0.5"


def test_dashboard_serves_report_files(tmp_path):
    report_id = _write_report_bundle(tmp_path)
    client = TestClient(create_app(output_dir=str(tmp_path)))

    response = client.get(f"/api/reports/{report_id}/files/json")

    assert response.status_code == 200
    assert json.loads(response.text)["meta"]["target"] == "10.0.0.0/24"


def test_dashboard_rejects_unsafe_scan_without_public_authorization(tmp_path):
    client = TestClient(create_app(output_dir=str(tmp_path)))

    response = client.post(
        "/api/scans",
        json={
            "target": "8.8.8.8",
            "ports": "80",
            "authorize_scan": False,
            "allow_public_targets": False,
        },
    )

    assert response.status_code == 400
    assert "Public targets require" in response.json()["detail"]


def test_dashboard_rejects_new_scan_when_one_is_active(tmp_path):
    app = create_app(output_dir=str(tmp_path))
    app.state.jobs["active"] = {
        "id": "active",
        "status": "running",
        "created_at": "2026-01-01T00:00:00+00:00",
        "started_at": "2026-01-01T00:00:01+00:00",
        "finished_at": "",
        "error": "",
        "stage": "scanning",
        "message": "Scanning 1 host",
        "request": {},
        "summary": None,
        "paths": {},
        "report_id": "",
    }
    client = TestClient(app)

    response = client.post(
        "/api/scans",
        json={
            "target": "127.0.0.1",
            "ports": "80",
            "authorize_scan": True,
        },
    )

    assert response.status_code == 409
    assert "already running" in response.json()["detail"]


def test_dashboard_rejects_report_path_traversal(tmp_path):
    client = TestClient(create_app(output_dir=str(tmp_path)))

    response = client.get("/api/reports/..%2Fsecret")

    assert response.status_code == 404
