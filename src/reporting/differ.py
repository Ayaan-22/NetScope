"""Diff two NetScope JSON reports."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScanDiff:
    old_report: str
    new_report: str
    new_open_ports: list[dict[str, Any]] = field(default_factory=list)
    closed_ports: list[dict[str, Any]] = field(default_factory=list)
    new_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    resolved_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    risk_changes: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_report": self.old_report,
            "new_report": self.new_report,
            "new_open_ports": self.new_open_ports,
            "closed_ports": self.closed_ports,
            "new_vulnerabilities": self.new_vulnerabilities,
            "resolved_vulnerabilities": self.resolved_vulnerabilities,
            "risk_changes": self.risk_changes,
            "summary": {
                "new_open_ports": len(self.new_open_ports),
                "closed_ports": len(self.closed_ports),
                "new_vulnerabilities": len(self.new_vulnerabilities),
                "resolved_vulnerabilities": len(self.resolved_vulnerabilities),
                "risk_changes": len(self.risk_changes),
            },
        }


def _load_report(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _port_key(row: dict[str, Any]) -> tuple[str, int]:
    return str(row["host"]), int(row["port"])


def _vuln_keys(row: dict[str, Any]) -> set[str]:
    return {str(v.get("cve_id")) for v in row.get("vulnerabilities", []) if v.get("cve_id")}


def diff_reports(old_path: str, new_path: str) -> ScanDiff:
    """Compare two NetScope JSON reports."""
    old = _load_report(old_path)
    new = _load_report(new_path)

    old_ports = {_port_key(row): row for row in old.get("results", [])}
    new_ports = {_port_key(row): row for row in new.get("results", [])}

    diff = ScanDiff(old_report=old_path, new_report=new_path)

    for key in sorted(new_ports.keys() - old_ports.keys()):
        row = new_ports[key]
        diff.new_open_ports.append(
            {
                "host": key[0],
                "port": key[1],
                "service": row.get("service", "unknown"),
                "risk_score": row.get("risk_score", 0.0),
            }
        )

    for key in sorted(old_ports.keys() - new_ports.keys()):
        row = old_ports[key]
        diff.closed_ports.append(
            {
                "host": key[0],
                "port": key[1],
                "service": row.get("service", "unknown"),
                "previous_risk_score": row.get("risk_score", 0.0),
            }
        )

    for key in sorted(new_ports.keys() & old_ports.keys()):
        old_row = old_ports[key]
        new_row = new_ports[key]
        old_vulns = _vuln_keys(old_row)
        new_vulns = _vuln_keys(new_row)

        for cve_id in sorted(new_vulns - old_vulns):
            diff.new_vulnerabilities.append({"host": key[0], "port": key[1], "cve_id": cve_id})
        for cve_id in sorted(old_vulns - new_vulns):
            diff.resolved_vulnerabilities.append(
                {"host": key[0], "port": key[1], "cve_id": cve_id}
            )

        old_risk = float(old_row.get("risk_score", 0.0))
        new_risk = float(new_row.get("risk_score", 0.0))
        if old_risk != new_risk:
            diff.risk_changes.append(
                {
                    "host": key[0],
                    "port": key[1],
                    "old_risk_score": old_risk,
                    "new_risk_score": new_risk,
                    "delta": round(new_risk - old_risk, 2),
                }
            )

    return diff


def write_diff_json(diff: ScanDiff, output_path: str) -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(diff.to_dict(), indent=2), encoding="utf-8")
    return output_path
