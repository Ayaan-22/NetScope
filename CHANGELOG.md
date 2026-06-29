# Changelog

## Unreleased

- Added the FastAPI web dashboard with scan launch controls, report history, analytics charts, severity filters, evidence review, and direct HTML/JSON/CSV downloads.
- Added **Use My Network** local-network detection so the dashboard can fill the current private LAN target without manually running `ipconfig`.
- Added dashboard job stages, scanner progress logging to `logs/netscope.log`, and a one-active-scan guard to avoid accidentally stacking long LAN scans.

## 2.1.0 - 2026-06-27

- Applied production-readiness audit fixes for configuration precedence, report sanitization, Nmap OS detection, global concurrency, and Docker context hygiene.
- Added installable packaging with a `netscope` console command.
- Added CI, pre-commit configuration, and expanded development dependencies.
- Added scan metadata, authorization controls, TLS-aware probing, report diffing, and baseline comparison support.

## 2.0.0 - 2026-04-18

- Added high-fidelity discovery, CVSS-aware CVE scoring, Nmap enrichment chunking, async stability fixes, and multi-format reporting.
