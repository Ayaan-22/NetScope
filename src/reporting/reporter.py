"""
NetScope Reporting
Generates HTML, JSON, and CSV reports from scan results.
"""

import csv
import json
import logging
import html as html_lib
from datetime import datetime
from pathlib import Path
from typing import Optional

from scanner.engine import ScanSummary, PortResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>NetScope — Vulnerability Report</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --crit: #f85149; --high: #e3b341; --med: #d29922; --low: #3fb950;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: .25rem; }}
  h2 {{ color: var(--text); font-size: 1.15rem; margin: 1.5rem 0 .75rem; border-bottom: 1px solid var(--border); padding-bottom: .4rem; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 1.5rem; margin: 1rem 0 1.5rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: .75rem 1.25rem; }}
  .stat-value {{ font-size: 1.6rem; font-weight: 700; color: var(--accent); }}
  .stat-label {{ font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }}
  .high-risk {{ color: var(--crit); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; font-size: .875rem; }}
  thead th {{ background: #1c2129; color: var(--muted); text-align: left; padding: .6rem .9rem; font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid var(--border); }}
  tbody tr {{ border-bottom: 1px solid var(--border); transition: background .15s; }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: #1c2129; }}
  td {{ padding: .55rem .9rem; vertical-align: top; }}
  .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; }}
  .badge-crit {{ background: #3d0e0c; color: var(--crit); }}
  .badge-high {{ background: #2d2008; color: var(--high); }}
  .badge-med  {{ background: #2d1e08; color: var(--med); }}
  .badge-low  {{ background: #0d2b0e; color: var(--low); }}
  .badge-info {{ background: #0d1f3d; color: var(--accent); }}
  .risk-score {{ font-weight: 700; }}
  .risk-crit {{ color: var(--crit); }}
  .risk-high {{ color: var(--high); }}
  .risk-med  {{ color: var(--med); }}
  .risk-low  {{ color: var(--low); }}
  .banner {{ font-family: monospace; font-size: .78rem; color: var(--muted); max-width: 280px; word-break: break-all; white-space: pre-wrap; }}
  .vuln-list {{ list-style: none; }}
  .vuln-list li {{ margin-bottom: .3rem; font-size: .82rem; }}
  .none {{ color: var(--muted); font-size: .82rem; }}
  footer {{ margin-top: 2rem; color: var(--muted); font-size: .78rem; text-align: center; }}
</style>
</head>
<body>
<h1>🔍 NetScope — Vulnerability Report</h1>
<p style="color:var(--muted);font-size:.85rem;">Generated {timestamp} UTC</p>

<div class="meta">
  <div class="stat"><div class="stat-value">{target}</div><div class="stat-label">Target</div></div>
  <div class="stat"><div class="stat-value">{hosts_scanned}</div><div class="stat-label">Hosts Scanned</div></div>
  <div class="stat"><div class="stat-value">{open_ports}</div><div class="stat-label">Open Ports</div></div>
  <div class="stat"><div class="stat-value">{total_vulns}</div><div class="stat-label">Vulnerabilities</div></div>
  <div class="stat"><div class="stat-value high-risk">{high_risk_count}</div><div class="stat-label">High-Risk Hosts</div></div>
</div>

{high_risk_section}

<h2>Scan Results</h2>
<table>
<thead><tr>
  <th>Host</th><th>Port</th><th>Service</th><th>Version</th>
  <th>Risk Score</th><th>Banner</th><th>Vulnerabilities</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
<footer>NetScope · Scan started {scan_start} · ended {scan_end}</footer>
</body>
</html>
"""


def _severity_badge(severity: str) -> str:
    cls_map = {
        "critical": "crit", "high": "high",
        "medium": "med", "low": "low", "info": "info",
    }
    cls = cls_map.get(severity.lower(), "info")
    return f'<span class="badge badge-{cls}">{html_lib.escape(severity)}</span>'


def _risk_class(score: float) -> str:
    if score >= 9.0:
        return "risk-crit"
    if score >= 7.5:
        return "risk-high"
    if score >= 5.0:
        return "risk-med"
    return "risk-low"


def _build_row(r: PortResult) -> str:
    rc = _risk_class(r.risk_score)
    vuln_items = "".join(
        f'<li>{_severity_badge(v["severity"])} '
        f'<strong>{html_lib.escape(v["cve_id"])}</strong> — '
        f'{html_lib.escape(v["description"][:120])}</li>'
        for v in r.vulnerabilities
    )
    vuln_cell = (
        f'<ul class="vuln-list">{vuln_items}</ul>'
        if vuln_items
        else '<span class="none">—</span>'
    )
    banner_display = html_lib.escape(r.banner[:160]) + ("…" if len(r.banner) > 160 else "")
    return (
        f"<tr>"
        f"<td>{html_lib.escape(r.host)}</td>"
        f"<td><strong>{r.port}</strong></td>"
        f"<td>{html_lib.escape(r.service)}</td>"
        f"<td>{html_lib.escape(r.version)}</td>"
        f"<td><span class='risk-score {rc}'>{r.risk_score:.1f}/10</span></td>"
        f"<td><div class='banner'>{banner_display}</div></td>"
        f"<td>{vuln_cell}</td>"
        f"</tr>"
    )


def generate_html(summary: ScanSummary, output_path: str = "reports/report.html") -> str:
    rows = "\n".join(_build_row(r) for r in summary.results)

    if summary.high_risk_hosts:
        hosts_str = ", ".join(
            f"<code>{html_lib.escape(h)}</code>" for h in summary.high_risk_hosts
        )
        high_risk_section = (
            f'<p style="background:#1c0a0a;border:1px solid var(--crit);'
            f'border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;">'
            f'⚠️ <strong>High-Risk Hosts:</strong> {hosts_str}</p>'
        )
    else:
        high_risk_section = ""

    html = _HTML_TEMPLATE.format(
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        target=html_lib.escape(summary.target),
        hosts_scanned=summary.hosts_scanned,
        open_ports=summary.open_ports,
        total_vulns=summary.total_vulns,
        high_risk_count=len(summary.high_risk_hosts),
        high_risk_section=high_risk_section,
        scan_start=html_lib.escape(summary.scan_start),
        scan_end=html_lib.escape(summary.scan_end),
        rows=rows,
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html, encoding="utf-8")
    logger.info("HTML report → %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

def generate_json(summary: ScanSummary, output_path: str = "reports/report.json") -> str:
    data = {
        "meta": {
            "target": summary.target,
            "hosts_scanned": summary.hosts_scanned,
            "open_ports": summary.open_ports,
            "total_vulnerabilities": summary.total_vulns,
            "high_risk_hosts": summary.high_risk_hosts,
            "scan_start": summary.scan_start,
            "scan_end": summary.scan_end,
            "generated": datetime.utcnow().isoformat(),
        },
        "results": [r.to_dict() for r in summary.results],
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logger.info("JSON report → %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# CSV Report
# ---------------------------------------------------------------------------

def generate_csv(summary: ScanSummary, output_path: str = "reports/report.csv") -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["Host", "Port", "Protocol", "State", "Service", "Version",
             "Risk Score", "CVE Count", "CVE IDs", "Banner"]
        )
        for r in summary.results:
            cve_ids = "; ".join(v["cve_id"] for v in r.vulnerabilities)
            writer.writerow(
                [r.host, r.port, r.protocol, r.state, r.service, r.version,
                 f"{r.risk_score:.1f}", len(r.vulnerabilities), cve_ids,
                 r.banner[:200]]
            )
    logger.info("CSV report → %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Multi-format exporter
# ---------------------------------------------------------------------------

def export_all(
    summary: ScanSummary,
    output_dir: str = "reports",
    prefix: str = "netscope",
    formats: Optional[list] = None,
) -> dict:
    """Export to all requested formats. Returns dict of {format: path}."""
    if formats is None:
        formats = ["html", "json", "csv"]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out: dict = {}
    for fmt in formats:
        path = f"{output_dir}/{prefix}_{ts}.{fmt}"
        if fmt == "html":
            out["html"] = generate_html(summary, path)
        elif fmt == "json":
            out["json"] = generate_json(summary, path)
        elif fmt == "csv":
            out["csv"] = generate_csv(summary, path)
        else:
            logger.warning("Unknown report format '%s' — skipped.", fmt)
    return out
