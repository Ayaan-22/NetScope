"""
NetScope Reporting
Generates HTML, JSON, and CSV reports from scan results.
"""

import csv
import json
import logging
import html as html_lib
import re
from datetime import datetime, timezone
from pathlib import Path

from src.scanner.engine import ScanSummary, PortResult

logger = logging.getLogger(__name__)

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_text(value: str, limit: int | None = None) -> str:
    """Remove control characters from untrusted banner/report text."""
    cleaned = _CONTROL_CHARS.sub("", value)
    return cleaned[:limit] if limit is not None else cleaned


def _sanitize_csv_cell(value: str, limit: int | None = None) -> str:
    cleaned = _sanitize_text(value, limit)
    if cleaned.startswith(_CSV_FORMULA_PREFIXES):
        return f"'{cleaned}"
    return cleaned


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>NetScope - Vulnerability Report</title>
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
  .controls {{ margin: 1rem 0 .75rem; display: flex; gap: .75rem; flex-wrap: wrap; }}
  .controls input {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; color: var(--text); padding: .5rem .65rem; min-width: 260px; }}
  th.sortable {{ cursor: pointer; }}
  .vuln-list {{ list-style: none; }}
  .vuln-list li {{ margin-bottom: .3rem; font-size: .82rem; }}
  .none {{ color: var(--muted); font-size: .82rem; }}
  footer {{ margin-top: 2rem; color: var(--muted); font-size: .78rem; text-align: center; }}
</style>
</head>
<body>
<h1>[!] NetScope - Vulnerability Report</h1>
<p style="color:var(--muted);font-size:.85rem;">Generated {timestamp} UTC</p>

<div class="meta">
  <div class="stat"><div class="stat-value">{target}</div><div class="stat-label">Target</div></div>
  <div class="stat"><div class="stat-value">{hosts_scanned}</div><div class="stat-label">Hosts Scanned</div></div>
  <div class="stat"><div class="stat-value">{open_ports}</div><div class="stat-label">Open Ports</div></div>
  <div class="stat"><div class="stat-value">{total_vulns}</div><div class="stat-label">Vulnerabilities</div></div>
  <div class="stat"><div class="stat-value high-risk">{high_risk_count}</div><div class="stat-label">High-Risk Hosts</div></div>
</div>

{high_risk_section}

{metadata_section}

<h2>Scan Results</h2>
<div class="controls">
  <input id="result-search" type="search" placeholder="Search host, hostname, service, banner, CVE" oninput="filterRows()"/>
</div>
<table id="results-table">
<thead><tr>
  <th class="sortable" onclick="sortTable(0)">Host</th>
  <th class="sortable" onclick="sortTable(1)">Hostname</th>
  <th class="sortable" onclick="sortTable(2)">MAC</th>
  <th class="sortable" onclick="sortTable(3, true)">Port</th>
  <th class="sortable" onclick="sortTable(4)">Service</th>
  <th class="sortable" onclick="sortTable(5)">Version</th>
  <th class="sortable" onclick="sortTable(6, true)">Risk Score</th>
  <th>Banner</th><th>Vulnerabilities</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
<footer>NetScope | Scan started {scan_start} | ended {scan_end}</footer>
<script src="{script_name}"></script>
</body>
</html>
"""

_REPORT_JS = """\
function filterRows() {
  const q = document.getElementById('result-search').value.toLowerCase();
  for (const row of document.querySelectorAll('#results-table tbody tr')) {
    row.style.display = row.dataset.search.includes(q) ? '' : 'none';
  }
}
function sortTable(col, numeric = false) {
  const tbody = document.querySelector('#results-table tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const asc = tbody.dataset.sortCol != col || tbody.dataset.sortDir === 'desc';
  rows.sort((a, b) => {
    const av = a.children[col].innerText.replace('/10', '').trim();
    const bv = b.children[col].innerText.replace('/10', '').trim();
    const cmp = numeric ? (parseFloat(av) || 0) - (parseFloat(bv) || 0) : av.localeCompare(bv);
    return asc ? cmp : -cmp;
  });
  tbody.dataset.sortCol = col;
  tbody.dataset.sortDir = asc ? 'asc' : 'desc';
  rows.forEach(row => tbody.appendChild(row));
}
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
    vuln_items = ""
    for v in r.vulnerabilities:
        cve_id = html_lib.escape(v["cve_id"])
        reference_url = v.get("reference_url", "")
        if reference_url:
            cve_html = f'<a href="{html_lib.escape(reference_url, quote=True)}">{cve_id}</a>'
        else:
            cve_html = f"<strong>{cve_id}</strong>"
        confidence = v.get("match_confidence", "unknown")
        vuln_items += (
            f'<li>{_severity_badge(v["severity"])} '
            f"{cve_html} - {html_lib.escape(v['description'][:120])} "
            f'<span class="none">({html_lib.escape(confidence)})</span></li>'
        )
    vuln_cell = (
        f'<ul class="vuln-list">{vuln_items}</ul>'
        if vuln_items
        else '<span class="none">-</span>'
    )
    banner_display = html_lib.escape(r.banner[:160]) + ("..." if len(r.banner) > 160 else "")
    search_text = " ".join(
        [
            r.host,
            r.hostname,
            r.mac_address,
            str(r.port),
            r.service,
            r.version,
            r.banner,
            " ".join(v.get("cve_id", "") for v in r.vulnerabilities),
            " ".join(v.get("severity", "") for v in r.vulnerabilities),
        ]
    ).lower()
    return (
        f'<tr data-search="{html_lib.escape(search_text, quote=True)}">'
        f"<td>{html_lib.escape(r.host)}</td>"
        f"<td>{html_lib.escape(r.hostname)}</td>"
        f"<td>{html_lib.escape(r.mac_address)}</td>"
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
            f'[!] <strong>High-Risk Hosts:</strong> {hosts_str}</p>'
        )
    else:
        high_risk_section = ""

    metadata_rows = "".join(
        f"<tr><td>{html_lib.escape(str(key))}</td>"
        f"<td>{html_lib.escape(str(value))}</td></tr>"
        for key, value in sorted(summary.metadata.items())
        if value
    )
    metadata_section = (
        f"<h2>Scan Metadata</h2><table><tbody>{metadata_rows}</tbody></table>"
        if metadata_rows
        else ""
    )

    html = _HTML_TEMPLATE.format(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        target=html_lib.escape(summary.target),
        hosts_scanned=summary.hosts_scanned,
        open_ports=summary.open_ports,
        total_vulns=summary.total_vulns,
        high_risk_count=len(summary.high_risk_hosts),
        high_risk_section=high_risk_section,
        metadata_section=metadata_section,
        scan_start=html_lib.escape(summary.scan_start),
        scan_end=html_lib.escape(summary.scan_end),
        script_name=html_lib.escape(Path(output_path).with_suffix(".js").name),
        rows=rows,
    )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html, encoding="utf-8")
    Path(output_path).with_suffix(".js").write_text(_REPORT_JS, encoding="utf-8")
    logger.info("HTML report -> %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

def generate_json(summary: ScanSummary, output_path: str = "reports/report.json") -> str:
    results = []
    for result in summary.results:
        item = result.to_dict()
        item["banner"] = _sanitize_text(item.get("banner", ""))
        results.append(item)

    data = {
        "meta": {
            "target": summary.target,
            "hosts_targeted": summary.hosts_targeted,
            "hosts_with_results": summary.hosts_with_results,
            "hosts_scanned": summary.hosts_scanned,
            "open_ports": summary.open_ports,
            "total_vulnerabilities": summary.total_vulns,
            "high_risk_hosts": summary.high_risk_hosts,
            "scan_start": summary.scan_start,
            "scan_end": summary.scan_end,
            "generated": datetime.now(timezone.utc).isoformat(),
            **summary.metadata,
        },
        "results": results,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logger.info("JSON report -> %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# CSV Report
# ---------------------------------------------------------------------------

def generate_csv(summary: ScanSummary, output_path: str = "reports/report.csv") -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["Host", "Hostname", "MAC Address", "Port", "Protocol", "State", "Service", "Version",
             "Risk Score", "CVE Count", "CVE IDs", "CVE References",
             "Match Confidence", "Banner"]
        )
        for r in summary.results:
            cve_ids = "; ".join(v["cve_id"] for v in r.vulnerabilities)
            cve_refs = "; ".join(v.get("reference_url", "") for v in r.vulnerabilities)
            confidence = "; ".join(v.get("match_confidence", "") for v in r.vulnerabilities)
            writer.writerow(
                [_sanitize_csv_cell(r.host), _sanitize_csv_cell(r.hostname),
                 _sanitize_csv_cell(r.mac_address), r.port, r.protocol, r.state,
                 _sanitize_csv_cell(r.service), _sanitize_csv_cell(r.version),
                 f"{r.risk_score:.1f}", len(r.vulnerabilities), cve_ids,
                 cve_refs, confidence,
                 _sanitize_csv_cell(r.banner, 200)]
            )
    logger.info("CSV report -> %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Multi-format exporter
# ---------------------------------------------------------------------------

def export_all(
    summary: ScanSummary,
    output_dir: str = "reports",
    prefix: str = "netscope",
    formats: list | None = None,
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
            logger.warning("Unknown report format '%s' - skipped.", fmt)
    return out
