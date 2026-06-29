"""FastAPI-powered NetScope web dashboard."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import platform
import re
import socket
import subprocess  # nosec B404
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from main import config_file_hash, expand_excluded_hosts, validate_scan_safety
from src import __version__
from src.reporting.reporter import export_all
from src.scanner.engine import NetScopeScanner, ScanSummary, validate_ports, validate_target
from src.utils.config import ALL_PORTS, COMMON_PORTS, TOP_1000_PORTS, ScanConfig
from src.utils.log_config import setup_logging

STATIC_DIR = Path(__file__).resolve().parent / "static"
REPORT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
IPV4_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
MAX_AUTO_NETWORK_ADDRESSES = 65536
ReportFormat = Literal["html", "json", "csv"]


def _default_report_formats() -> list[ReportFormat]:
    return ["html", "json", "csv"]


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    ports: str = Field(default="common", max_length=256)
    discover_first: bool = False
    timeout: float = Field(default=1.5, ge=0.1, le=30.0)
    concurrency: int = Field(default=500, ge=1, le=5000)
    batch_size: int = Field(default=20, ge=1, le=512)
    probe_delay: float = Field(default=0.0, ge=0.0, le=10.0)
    probe_jitter: float = Field(default=0.0, ge=0.0, le=10.0)
    max_results: int = Field(default=100000, ge=1, le=1000000)
    use_nmap: bool = True
    nmap_os_detect: bool = False
    nmap_timing: int = Field(default=4, ge=0, le=5)
    authorize_scan: bool = False
    allow_public_targets: bool = False
    exclude: list[str] = Field(default_factory=list)
    formats: list[ReportFormat] = Field(default_factory=_default_report_formats)

    @field_validator("ports")
    @classmethod
    def _ports_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("ports cannot be blank")
        return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_ports(spec: str) -> list[int]:
    if spec == "common":
        return COMMON_PORTS
    if spec == "top1000":
        return TOP_1000_PORTS
    if spec == "all":
        return ALL_PORTS
    return validate_ports(spec)


def _is_usable_local_ip(address: ipaddress.IPv4Address) -> bool:
    return (
        address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
    )


def _network_candidate(
    ip_value: str,
    mask_value: str | None = None,
    *,
    adapter: str = "Local adapter",
    gateway: str = "",
    source: str = "system",
) -> dict[str, Any] | None:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address) or not _is_usable_local_ip(address):
        return None

    capped = False
    try:
        network = ipaddress.ip_interface(
            f"{address}/{mask_value}" if mask_value else f"{address}/24"
        ).network
    except ValueError:
        network = ipaddress.ip_interface(f"{address}/24").network
        capped = True

    if network.num_addresses > MAX_AUTO_NETWORK_ADDRESSES:
        network = ipaddress.ip_interface(f"{address}/24").network
        capped = True

    return {
        "target": str(network),
        "ip": str(address),
        "netmask": mask_value or "255.255.255.0",
        "prefix": network.prefixlen,
        "adapter": adapter,
        "gateway": gateway,
        "source": source,
        "capped": capped,
        "usable_hosts": max(network.num_addresses - 2, 1),
        "score": (40 if gateway else 0) + (20 if not capped else 0) + (10 if "wi-fi" in adapter.lower() else 0),
    }


def _dedupe_networks(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best_by_target: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        current = best_by_target.get(candidate["target"])
        if current is None or candidate["score"] > current["score"]:
            best_by_target[candidate["target"]] = candidate
    ranked = sorted(
        best_by_target.values(),
        key=lambda item: (-item["score"], item["target"], item["adapter"]),
    )
    for item in ranked:
        item.pop("score", None)
    return ranked


def _extract_first_ipv4(value: str) -> str:
    match = IPV4_RE.search(value)
    return match.group(1) if match else ""


def _windows_local_networks() -> list[dict[str, Any]]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        output = subprocess.check_output(  # nosec
            ["ipconfig", "/all"],
            text=True,
            encoding="utf-8",
            errors="ignore",
            stderr=subprocess.DEVNULL,
            timeout=4,
            creationflags=flags,
        )
    except Exception:
        return []

    candidates: list[dict[str, Any]] = []
    adapter = "Local adapter"
    ip_value = ""
    mask_value = ""
    gateway = ""
    disconnected = False

    def flush() -> None:
        nonlocal ip_value, mask_value, gateway, disconnected
        if ip_value and mask_value and not disconnected:
            candidate = _network_candidate(
                ip_value,
                mask_value,
                adapter=adapter.rstrip(":"),
                gateway=gateway,
                source="ipconfig",
            )
            if candidate:
                candidates.append(candidate)
        ip_value = ""
        mask_value = ""
        gateway = ""
        disconnected = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if raw_line and not raw_line.startswith((" ", "\t")) and line.endswith(":"):
            flush()
            adapter = line
            continue
        lowered = line.lower()
        if "media disconnected" in lowered:
            disconnected = True
        elif "ipv4" in lowered:
            ip_value = _extract_first_ipv4(line)
        elif "subnet mask" in lowered:
            mask_value = _extract_first_ipv4(line)
        elif "default gateway" in lowered and not gateway:
            gateway = _extract_first_ipv4(line)
    flush()
    return candidates


def _socket_local_networks() -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    probe_hosts = ("8.8.8.8", "1.1.1.1")
    for probe_host in probe_hosts:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((probe_host, 80))
            ip_value = sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
        if ip_value in seen:
            continue
        seen.add(ip_value)
        candidate = _network_candidate(
            ip_value,
            None,
            adapter="Default route",
            source="socket",
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def detect_local_networks() -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if platform.system() == "Windows":
        candidates.extend(_windows_local_networks())
    candidates.extend(_socket_local_networks())
    return _dedupe_networks(candidates)


def _result_to_dict(result: Any) -> dict[str, Any]:
    return result.to_dict() if hasattr(result, "to_dict") else dict(result)


def _summary_to_dict(summary: ScanSummary) -> dict[str, Any]:
    return {
        "target": summary.target,
        "hosts_targeted": summary.hosts_targeted,
        "hosts_with_results": summary.hosts_with_results,
        "hosts_scanned": summary.hosts_scanned,
        "open_ports": summary.open_ports,
        "total_vulns": summary.total_vulns,
        "high_risk_hosts": summary.high_risk_hosts,
        "scan_start": summary.scan_start,
        "scan_end": summary.scan_end,
        "metadata": summary.metadata,
        "results": [_result_to_dict(result) for result in summary.results],
    }


def _empty_summary(target: str, hosts_targeted: int, metadata: dict[str, str]) -> ScanSummary:
    now = _utc_now()
    return ScanSummary(
        target=target,
        hosts_targeted=hosts_targeted,
        hosts_with_results=0,
        open_ports=0,
        total_vulns=0,
        high_risk_hosts=[],
        scan_start=now,
        scan_end=now,
        results=[],
        metadata=metadata,
    )


def _severity_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for result in results:
        for vuln in result.get("vulnerabilities", []):
            severity = str(vuln.get("severity", "info")).lower()
            if severity not in counts:
                severity = "info"
            counts[severity] += 1
    return counts


def _top_counts(results: list[dict[str, Any]], key: str, limit: int = 8) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for result in results:
        value = str(result.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [{"name": name, "count": count} for name, count in ranked]


def _risk_buckets(results: list[dict[str, Any]]) -> dict[str, int]:
    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for result in results:
        score = float(result.get("risk_score") or 0)
        if score >= 9:
            buckets["critical"] += 1
        elif score >= 7.5:
            buckets["high"] += 1
        elif score >= 5:
            buckets["medium"] += 1
        else:
            buckets["low"] += 1
    return buckets


def _analytics(report: dict[str, Any]) -> dict[str, Any]:
    results = report.get("results", [])
    hosts = sorted({result.get("host", "unknown") for result in results})
    cves = sorted(
        {
            vuln.get("cve_id")
            for result in results
            for vuln in result.get("vulnerabilities", [])
            if vuln.get("cve_id")
        }
    )
    return {
        "severity_counts": _severity_counts(results),
        "risk_buckets": _risk_buckets(results),
        "top_services": _top_counts(results, "service"),
        "top_ports": _top_counts(results, "port"),
        "hosts": hosts,
        "unique_cves": cves,
        "host_count": len(hosts),
        "cve_count": len(cves),
    }


def _safe_report_id(report_id: str) -> str:
    if not REPORT_ID_RE.fullmatch(report_id):
        raise HTTPException(status_code=404, detail="Report not found")
    return report_id


def _report_paths(output_dir: Path, report_id: str) -> dict[str, Path]:
    safe_id = _safe_report_id(report_id)
    return {
        "json": output_dir / f"{safe_id}.json",
        "html": output_dir / f"{safe_id}.html",
        "csv": output_dir / f"{safe_id}.csv",
    }


def _load_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def _report_preview(path: Path, output_dir: Path) -> dict[str, Any]:
    report = _load_report(path)
    meta = report.get("meta", {})
    results = report.get("results", [])
    report_id = path.stem
    siblings = _report_paths(output_dir, report_id)
    analytics = _analytics(report)
    return {
        "id": report_id,
        "target": meta.get("target", ""),
        "generated": meta.get("generated", ""),
        "scan_start": meta.get("scan_start", ""),
        "scan_end": meta.get("scan_end", ""),
        "hosts_targeted": meta.get("hosts_targeted", meta.get("hosts_scanned", 0)),
        "hosts_with_results": meta.get("hosts_with_results", meta.get("hosts_scanned", 0)),
        "open_ports": len(results),
        "total_vulnerabilities": meta.get("total_vulnerabilities", 0),
        "high_risk_hosts": meta.get("high_risk_hosts", []),
        "severity_counts": analytics["severity_counts"],
        "files": {kind: file.exists() for kind, file in siblings.items()},
    }


async def _run_scan_job(
    app: FastAPI,
    job_id: str,
    request: ScanRequest,
    config: ScanConfig,
    config_path: str,
    output_dir: Path,
) -> None:
    job = app.state.jobs[job_id]
    job["status"] = "running"
    job["stage"] = "starting"
    job["message"] = "Preparing scan"
    job["started_at"] = _utc_now()
    logger = app.state.logger

    try:
        ports = _resolve_ports(request.ports)
        excluded_hosts = expand_excluded_hosts(request.exclude)
        logger.info(
            "Dashboard scan %s started: target=%s ports=%s discover_first=%s nmap=%s",
            job_id,
            request.target,
            request.ports,
            request.discover_first,
            request.use_nmap,
        )
        metadata = {
            "session_id": job_id,
            "tool_version": __version__,
            "scanner_host": socket.gethostname(),
            "dashboard": "true",
            "config_path": str(Path(config_path)),
            "config_sha256": config_file_hash(config_path),
            "authorized_scan": str(request.authorize_scan),
            "allow_public_targets": str(request.allow_public_targets),
        }

        with NetScopeScanner(
            target=request.target,
            ports=ports,
            timeout=request.timeout,
            concurrency=request.concurrency,
            use_nmap=request.use_nmap,
            nmap_timing=request.nmap_timing,
            nmap_os_detect=request.nmap_os_detect,
            nmap_timeout=config.nmap_timeout,
            nmap_discovery_timeout=config.nmap_discovery_timeout,
            cve_db_path=config.cve_db_path,
            excluded_hosts=excluded_hosts,
            probe_delay=request.probe_delay,
            probe_jitter=request.probe_jitter,
            max_results=request.max_results,
            scan_metadata=metadata,
            host_batch_size=request.batch_size,
        ) as scanner:
            if request.discover_first:
                job["stage"] = "discovery"
                job["message"] = f"Discovering active hosts in {request.target}"
                active_hosts = await scanner.discover_hosts()
                logger.info(
                    "Dashboard scan %s discovery found %d active hosts",
                    job_id,
                    len(active_hosts),
                )
                if not active_hosts:
                    summary = _empty_summary(request.target, len(scanner.hosts), metadata)
                else:
                    scanner.hosts = active_hosts
                    job["stage"] = "scanning"
                    job["message"] = f"Scanning {len(active_hosts)} discovered host(s)"
                    summary = await scanner.run()
            else:
                job["stage"] = "scanning"
                job["message"] = f"Scanning {len(scanner.hosts)} host(s)"
                summary = await scanner.run()

        job["stage"] = "exporting"
        job["message"] = "Writing HTML, JSON, and CSV reports"
        paths = export_all(
            summary,
            output_dir=str(output_dir),
            prefix=config.report_prefix,
            formats=list(request.formats),
        )
        report_id = Path(paths["json"]).stem if "json" in paths else ""
        job.update(
            {
                "status": "completed",
                "stage": "completed",
                "message": (
                    f"Completed: {summary.open_ports} open port(s), "
                    f"{summary.total_vulns} vulnerability match(es)"
                ),
                "finished_at": _utc_now(),
                "summary": _summary_to_dict(summary),
                "paths": paths,
                "report_id": report_id,
            }
        )
        logger.info(
            "Dashboard scan %s completed: open_ports=%d vulnerabilities=%d report_id=%s",
            job_id,
            summary.open_ports,
            summary.total_vulns,
            report_id,
        )
    except Exception as exc:
        logger.exception("Dashboard scan %s failed: %s", job_id, exc)
        job.update(
            {
                "status": "failed",
                "stage": "failed",
                "message": "Scan failed",
                "finished_at": _utc_now(),
                "error": str(exc),
            }
        )


def create_app(
    config_path: str = "config/settings.yaml",
    output_dir: str | None = None,
) -> FastAPI:
    config = ScanConfig.load(config_path)
    report_dir = Path(output_dir or config.output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(level=config.log_level, log_dir=config.log_dir)

    app = FastAPI(title="NetScope Dashboard", version=__version__)
    app.state.jobs = {}
    app.state.config = config
    app.state.config_path = config_path
    app.state.output_dir = report_dir
    app.state.logger = __import__("logging").getLogger(__name__)

    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/defaults")
    async def defaults() -> dict[str, Any]:
        payload = asdict(config)
        payload["ports"] = "common" if payload["ports"] == COMMON_PORTS else payload["ports"]
        payload["output_dir"] = str(report_dir)
        return payload

    @app.get("/api/local-networks")
    async def local_networks() -> dict[str, Any]:
        networks = detect_local_networks()
        return {"networks": networks, "recommended": networks[0] if networks else None}

    @app.get("/api/jobs")
    async def jobs() -> list[dict[str, Any]]:
        return sorted(app.state.jobs.values(), key=lambda item: item["created_at"], reverse=True)

    @app.post("/api/scans", status_code=202)
    async def launch_scan(request: ScanRequest) -> dict[str, Any]:
        active_jobs = [
            job for job in app.state.jobs.values()
            if job["status"] in {"queued", "running"}
        ]
        if active_jobs:
            raise HTTPException(
                status_code=409,
                detail=(
                    "A scan is already running. Wait for it to finish before "
                    "starting another LAN scan."
                ),
            )

        try:
            hosts = validate_target(request.target)
            excluded_hosts = expand_excluded_hosts(request.exclude)
            remaining_hosts = [host for host in hosts if host not in set(excluded_hosts)]
            if not remaining_hosts:
                raise ValueError("all hosts were excluded")
            validate_scan_safety(
                remaining_hosts,
                authorized_scan=request.authorize_scan,
                allow_public_targets=request.allow_public_targets,
            )
            _resolve_ports(request.ports)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        job_id = str(uuid.uuid4())
        job = {
            "id": job_id,
            "status": "queued",
            "created_at": _utc_now(),
            "started_at": "",
            "finished_at": "",
            "error": "",
            "stage": "queued",
            "message": "Waiting to start",
            "request": request.model_dump(),
            "summary": None,
            "paths": {},
            "report_id": "",
        }
        app.state.jobs[job_id] = job
        asyncio.create_task(_run_scan_job(app, job_id, request, config, config_path, report_dir))
        return job

    @app.get("/api/jobs/{job_id}")
    async def job_status(job_id: str) -> dict[str, Any]:
        if job_id not in app.state.jobs:
            raise HTTPException(status_code=404, detail="Job not found")
        return app.state.jobs[job_id]

    @app.get("/api/reports")
    async def reports() -> list[dict[str, Any]]:
        files = sorted(report_dir.glob("*.json"), key=lambda file: file.stat().st_mtime, reverse=True)
        return [_report_preview(file, report_dir) for file in files]

    @app.get("/api/reports/{report_id}")
    async def report_detail(report_id: str) -> dict[str, Any]:
        paths = _report_paths(report_dir, report_id)
        report = _load_report(paths["json"])
        return {
            "id": report_id,
            "meta": report.get("meta", {}),
            "results": report.get("results", []),
            "analytics": _analytics(report),
            "files": {kind: file.exists() for kind, file in paths.items()},
        }

    @app.get("/api/reports/{report_id}/files/{kind}")
    async def report_file(report_id: str, kind: Literal["json", "html", "csv"]) -> FileResponse:
        path = _report_paths(report_dir, report_id)[kind]
        if not path.exists():
            raise HTTPException(status_code=404, detail="Report file not found")
        media_type = {
            "json": "application/json",
            "html": "text/html",
            "csv": "text/csv",
        }[kind]
        return FileResponse(path, media_type=media_type, filename=path.name)

    return app


app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the NetScope web dashboard.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8765, help="Bind port")
    parser.add_argument("--config", default="config/settings.yaml", help="YAML config path")
    parser.add_argument("--output-dir", default=None, help="Report directory override")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit("Install uvicorn to run the dashboard: pip install uvicorn") from exc

    uvicorn.run(create_app(args.config, args.output_dir), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
