import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.dashboard import app as dashboard_app
from src.dashboard.app import ScanRequest, create_app
from src.reporting.reporter import generate_csv, generate_html, generate_json
from src.scanner.engine import PortResult, ScanSummary
from src.utils.config import ScanConfig


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

    index = client.get("/")
    assert index.status_code == 200

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


def test_network_helpers_reject_invalid_and_unusable_addresses():
    assert dashboard_app._network_candidate("not-an-ip") is None
    assert dashboard_app._network_candidate("127.0.0.1") is None
    assert dashboard_app._network_candidate("192.168.1.20", "bad-mask")["capped"] is True


def test_windows_local_networks_parse_ipconfig(monkeypatch):
    output = """
Ethernet adapter Ethernet:
   Media State . . . . . . . . . . . : Media disconnected

Wireless LAN adapter Wi-Fi:
   IPv4 Address. . . . . . . . . . . : 192.168.50.23(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.1
"""
    monkeypatch.setattr(
        dashboard_app.subprocess,
        "check_output",
        lambda *args, **kwargs: output,
    )

    networks = dashboard_app._windows_local_networks()

    assert len(networks) == 1
    assert networks[0]["target"] == "192.168.50.0/24"
    assert networks[0]["adapter"] == "Wireless LAN adapter Wi-Fi"
    assert networks[0]["gateway"] == "192.168.50.1"


def test_windows_local_networks_handles_ipconfig_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("ipconfig unavailable")

    monkeypatch.setattr(dashboard_app.subprocess, "check_output", fail)

    assert dashboard_app._windows_local_networks() == []


def test_socket_local_networks_deduplicates_and_ignores_failures(monkeypatch):
    class FakeSocket:
        values = iter(["192.168.60.10", OSError("route unavailable")])

        def __init__(self, *args):
            self.value = next(self.values)
            self.closed = False

        def connect(self, address):
            if isinstance(self.value, OSError):
                raise self.value

        def getsockname(self):
            return (self.value, 53210)

        def close(self):
            self.closed = True

    monkeypatch.setattr(dashboard_app.socket, "socket", FakeSocket)

    networks = dashboard_app._socket_local_networks()

    assert [network["target"] for network in networks] == ["192.168.60.0/24"]
    assert networks[0]["source"] == "socket"


def test_detect_local_networks_combines_and_ranks(monkeypatch):
    monkeypatch.setattr(dashboard_app.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        dashboard_app,
        "_windows_local_networks",
        lambda: [
            {
                "target": "192.168.70.0/24",
                "ip": "192.168.70.5",
                "adapter": "Wi-Fi",
                "score": 70,
            }
        ],
    )
    monkeypatch.setattr(
        dashboard_app,
        "_socket_local_networks",
        lambda: [
            {
                "target": "192.168.70.0/24",
                "ip": "192.168.70.99",
                "adapter": "Default route",
                "score": 20,
            },
            {
                "target": "10.0.1.0/24",
                "ip": "10.0.1.5",
                "adapter": "Ethernet",
                "score": 30,
            },
        ],
    )

    networks = dashboard_app.detect_local_networks()

    assert [network["target"] for network in networks] == [
        "192.168.70.0/24",
        "10.0.1.0/24",
    ]
    assert networks[0]["ip"] == "192.168.70.5"
    assert "score" not in networks[0]


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


def test_dashboard_report_file_missing_returns_404(tmp_path):
    report_id = _write_report_bundle(tmp_path)
    (tmp_path / f"{report_id}.csv").unlink()
    client = TestClient(create_app(output_dir=str(tmp_path)))

    response = client.get(f"/api/reports/{report_id}/files/csv")

    assert response.status_code == 404
    assert response.json()["detail"] == "Report file not found"


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


def test_dashboard_launches_scan_and_exposes_job_status(tmp_path, monkeypatch):
    created = []

    def fake_create_task(coro):
        created.append(coro)
        coro.close()
        return None

    monkeypatch.setattr(dashboard_app.asyncio, "create_task", fake_create_task)
    client = TestClient(create_app(output_dir=str(tmp_path)))

    response = client.post(
        "/api/scans",
        json={
            "target": "127.0.0.1",
            "ports": "common",
            "authorize_scan": True,
            "formats": ["json"],
        },
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["request"]["ports"] == "common"
    assert len(created) == 1

    status = client.get(f"/api/jobs/{payload['id']}")
    assert status.status_code == 200
    assert status.json()["id"] == payload["id"]

    missing = client.get("/api/jobs/missing")
    assert missing.status_code == 404


class FakeScanner:
    instances = []
    discovered_hosts = ["10.0.0.5"]
    summary = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.hosts = ["10.0.0.5", "10.0.0.6"]
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    async def discover_hosts(self):
        return self.discovered_hosts

    async def run(self):
        return self.summary or _summary()


def _job(job_id: str) -> dict:
    return {
        "id": job_id,
        "status": "queued",
        "created_at": "2026-01-01T00:00:00+00:00",
        "started_at": "",
        "finished_at": "",
        "error": "",
        "stage": "queued",
        "message": "Waiting to start",
        "request": {},
        "summary": None,
        "paths": {},
        "report_id": "",
    }


def _patch_scan_job_dependencies(monkeypatch, tmp_path, scanner=FakeScanner):
    FakeScanner.instances = []
    FakeScanner.discovered_hosts = ["10.0.0.5"]
    FakeScanner.summary = _summary()
    monkeypatch.setattr(dashboard_app, "NetScopeScanner", scanner)
    monkeypatch.setattr(dashboard_app, "config_file_hash", lambda path: "hash")
    monkeypatch.setattr(
        dashboard_app,
        "export_all",
        lambda summary, output_dir, prefix, formats: {
            "json": str(Path(output_dir) / f"{prefix}.json"),
            "html": str(Path(output_dir) / f"{prefix}.html"),
        },
    )


@pytest.mark.asyncio
async def test_run_scan_job_completes_and_exports(tmp_path, monkeypatch):
    _patch_scan_job_dependencies(monkeypatch, tmp_path)
    app = create_app(output_dir=str(tmp_path))
    app.state.jobs["job-1"] = _job("job-1")
    request = ScanRequest(
        target="127.0.0.1",
        ports="80",
        authorize_scan=True,
        formats=["json", "html"],
    )
    config = ScanConfig(report_prefix="unit")

    await dashboard_app._run_scan_job(app, "job-1", request, config, "settings.yaml", tmp_path)

    job = app.state.jobs["job-1"]
    assert job["status"] == "completed"
    assert job["stage"] == "completed"
    assert job["summary"]["open_ports"] == 1
    assert job["report_id"] == "unit"
    assert FakeScanner.instances[0].kwargs["ports"] == [80]
    assert FakeScanner.instances[0].kwargs["scan_metadata"]["config_sha256"] == "hash"


@pytest.mark.asyncio
async def test_run_scan_job_discovery_without_hosts_exports_empty_summary(tmp_path, monkeypatch):
    _patch_scan_job_dependencies(monkeypatch, tmp_path)
    FakeScanner.discovered_hosts = []
    app = create_app(output_dir=str(tmp_path))
    app.state.jobs["job-2"] = _job("job-2")
    request = ScanRequest(
        target="127.0.0.1/32",
        ports="top1000",
        discover_first=True,
        authorize_scan=True,
        formats=["json"],
    )

    await dashboard_app._run_scan_job(app, "job-2", request, ScanConfig(), "settings.yaml", tmp_path)

    job = app.state.jobs["job-2"]
    assert job["status"] == "completed"
    assert job["summary"]["open_ports"] == 0
    assert job["summary"]["hosts_targeted"] == 2


@pytest.mark.asyncio
async def test_run_scan_job_records_failures(tmp_path, monkeypatch):
    class FailingScanner(FakeScanner):
        async def run(self):
            raise RuntimeError("scan exploded")

    _patch_scan_job_dependencies(monkeypatch, tmp_path, scanner=FailingScanner)
    app = create_app(output_dir=str(tmp_path))
    app.state.jobs["job-3"] = _job("job-3")
    request = ScanRequest(target="127.0.0.1", ports="all", authorize_scan=True)

    await dashboard_app._run_scan_job(app, "job-3", request, ScanConfig(), "settings.yaml", tmp_path)

    job = app.state.jobs["job-3"]
    assert job["status"] == "failed"
    assert job["stage"] == "failed"
    assert job["error"] == "scan exploded"


def test_dashboard_analytics_bucket_edge_cases():
    report = {
        "results": [
            {
                "host": "10.0.0.2",
                "service": "",
                "port": 22,
                "risk_score": 8.0,
                "vulnerabilities": [{"severity": "High", "cve_id": "CVE-1"}],
            },
            {
                "host": "10.0.0.3",
                "service": "http",
                "port": 80,
                "risk_score": 6.0,
                "vulnerabilities": [{"severity": "Unexpected", "cve_id": "CVE-2"}],
            },
            {
                "host": "10.0.0.4",
                "service": "http",
                "port": 8080,
                "risk_score": 1.0,
                "vulnerabilities": [],
            },
        ]
    }

    analytics = dashboard_app._analytics(report)

    assert analytics["severity_counts"]["high"] == 1
    assert analytics["severity_counts"]["info"] == 1
    assert analytics["risk_buckets"] == {
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 1,
    }
    assert analytics["top_services"][0] == {"name": "http", "count": 2}


def test_dashboard_rejects_report_path_traversal(tmp_path):
    client = TestClient(create_app(output_dir=str(tmp_path)))

    response = client.get("/api/reports/..%2Fsecret")

    assert response.status_code == 404
