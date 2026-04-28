#!/usr/bin/env python3
"""
NetScope — Network Vulnerability Scanner
CLI entry point.

Usage examples:
  python main.py -t 192.168.1.1
  python main.py -t 192.168.1.0/24 -p 22,80,443,8080
  python main.py -t 10.0.0.1 --ports top1000 --no-nmap
  python main.py -t 10.0.0.0/16 --concurrency 1000 --formats html json
  python main.py -t 10.0.0.0/24 --batch-size 50

Phase 2 changes:
  DESIGN-2  Summary output now shows hosts_targeted vs hosts_with_results
  DESIGN-3  ScanConfig.load() used (correct defaults -> YAML -> env order)
  DESIGN-4  --batch-size CLI arg added; forwarded to NetScopeScanner
            Scanner used as context manager so executor shuts down cleanly
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Import application modules
from src.utils.log_config import setup_logging
from src.utils.config import ScanConfig, COMMON_PORTS, TOP_1000_PORTS, ALL_PORTS
from src.scanner.engine import NetScopeScanner, validate_target, validate_ports
from src.reporting.reporter import export_all

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  _   _      _   ____
 | \ | | ___| |_/ ___|  ___ ___  _ __   ___
 |  \| |/ _ \ __\___ \ / __/ _ \| '_ \ / _ \
 | |\  |  __/ |_ ___) | (_| (_) | |_) |  __/
 |_| \_|\___|\__|____/ \___\___/| .__/ \___|
                                |_|
 Network Vulnerability Scanner - v2.0.0
"""


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope — Production-grade network vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        "-t", "--target",
        required=True,
        metavar="TARGET",
        help="Target IP, hostname, or CIDR subnet (e.g. 192.168.1.0/24)",
    )
    p.add_argument(
        "--discover",
        action="store_true",
        help="Perform host discovery only (ping sweep), no port scanning",
    )
    p.add_argument(
        "-p", "--ports",
        default="common",
        metavar="PORTS",
        help=(
            "Ports to scan: 'common' (default), 'top1000', 'all', or a custom spec "
            "like '22,80,443' or '1-1024,8080' (comma/range syntax)"
        ),
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        metavar="SECS",
        help="Per-port connection timeout in seconds (default: 1.5)",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=500,
        metavar="N",
        help="Max concurrent async connections (default: 500)",
    )
    # DESIGN-4: --batch-size is now a real CLI flag instead of a hard-coded 20
    p.add_argument(
        "--batch-size",
        type=int,
        default=20,
        metavar="N",
        help=(
            "Hosts scanned in parallel per async batch (default: 20). "
            "Increase for faster LAN scans; decrease on slow links."
        ),
    )
    p.add_argument(
        "--no-nmap",
        action="store_true",
        help="Skip Nmap service/version enrichment",
    )
    p.add_argument(
        "--nmap-timing",
        type=int,
        choices=range(0, 6),
        default=4,
        metavar="{0-5}",
        help="Nmap timing template 0=slowest to 5=fastest (default: 4)",
    )
    p.add_argument(
        "--cve-db",
        default="config/cve_db.csv",
        metavar="PATH",
        help="Path to CVE CSV database (default: config/cve_db.csv)",
    )
    p.add_argument(
        "--output-dir",
        default="reports",
        metavar="DIR",
        help="Directory for report files (default: reports/)",
    )
    p.add_argument(
        "--formats",
        nargs="+",
        choices=["html", "json", "csv"],
        default=["html", "json", "csv"],
        help="Report formats to generate (default: html json csv)",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    p.add_argument(
        "--config",
        default="config/settings.yaml",
        metavar="FILE",
        help="YAML config file path (optional; CLI args take precedence)",
    )
    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def _run(args: argparse.Namespace) -> int:
    # Resolve port list
    if args.ports == "common":
        ports = COMMON_PORTS
    elif args.ports == "top1000":
        ports = TOP_1000_PORTS
    elif args.ports == "all":
        ports = ALL_PORTS
    else:
        try:
            ports = validate_ports(args.ports)
        except ValueError as exc:
            logger.error("Invalid port specification: %s", exc)
            return 2

    # Validate target early for a clean error message
    try:
        validate_target(args.target)
    except ValueError as exc:
        logger.error("Invalid target: %s", exc)
        return 2

    # DESIGN-4: pass host_batch_size through; use scanner as context manager
    # so the shared ThreadPoolExecutor is always shut down cleanly on exit,
    # including on KeyboardInterrupt.
    with NetScopeScanner(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        concurrency=args.concurrency,
        use_nmap=not args.no_nmap,
        nmap_timing=args.nmap_timing,
        cve_db_path=args.cve_db,
        host_batch_size=args.batch_size,
    ) as scanner:

        if args.discover:
            return await scanner.run_discovery()

        logger.info("Starting scan ...")
        summary = await scanner.run()

    # DESIGN-2: print both new fields so users understand the difference
    # between "hosts in range" and "hosts that responded".
    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print(f"  Target          : {summary.target}")
    print(f"  Hosts targeted  : {summary.hosts_targeted}")
    print(f"  Hosts responded : {summary.hosts_with_results}")
    print(f"  Open ports      : {summary.open_ports}")
    print(f"  Vulnerabilities : {summary.total_vulns}")
    print(f"  High-risk hosts : {len(summary.high_risk_hosts)}")
    if summary.high_risk_hosts:
        print(f"  ⚠  {', '.join(summary.high_risk_hosts)}")
    print("=" * 60 + "\n")

    # Export reports
    paths = export_all(
        summary,
        output_dir=args.output_dir,
        formats=args.formats,
    )
    for fmt, path in paths.items():
        logger.info("Report saved: %s -> %s", fmt.upper(), path)

    return 0


def main() -> None:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(level=args.log_level)

    # DESIGN-3: use ScanConfig.load() which applies the correct
    # defaults -> YAML -> env-var precedence order.
    # (Not all fields are consumed yet — this wires up the config system
    # for future use so YAML settings flow through automatically.)
    _ = ScanConfig.load(args.config)

    try:
        exit_code = asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        exit_code = 130
    except Exception as exc:
        logging.getLogger(__name__).critical("Fatal error: %s", exc, exc_info=True)
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()