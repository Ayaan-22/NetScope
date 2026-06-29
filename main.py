#!/usr/bin/env python3
"""
NetScope - Network Vulnerability Scanner
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
import hashlib
import ipaddress
import logging
import sys
from dataclasses import replace
from pathlib import Path

# Import application modules
from src.utils.log_config import setup_logging
from src.utils.config import ScanConfig, COMMON_PORTS, TOP_1000_PORTS, ALL_PORTS
from src.scanner.engine import NetScopeScanner, validate_target, validate_ports
from src.reporting.reporter import export_all
from src.reporting.differ import diff_reports, write_diff_json
from src import __version__

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
 Network Vulnerability Scanner - v{version}
"""


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope - production-grade network vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        "-t", "--target",
        default=None,
        metavar="TARGET",
        help="Target IP, hostname, or CIDR subnet (e.g. 192.168.1.0/24)",
    )
    p.add_argument(
        "--discover",
        action="store_true",
        help="Perform host discovery only (ping sweep), no port scanning",
    )
    p.add_argument(
        "--discover-scan",
        action="store_true",
        help="Discover active hosts first, then scan only discovered hosts.",
    )
    p.add_argument(
        "-p", "--ports",
        default=None,
        metavar="PORTS",
        help=(
            "Ports to scan: 'common' (default), 'top1000', 'all', or a custom spec "
            "like '22,80,443' or '1-1024,8080' (comma/range syntax)"
        ),
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECS",
        help="Per-port connection timeout in seconds (default: 1.5)",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=None,
        metavar="N",
        help="Max concurrent async connections (default: 500)",
    )
    # DESIGN-4: --batch-size is now a real CLI flag instead of a hard-coded 20
    p.add_argument(
        "--batch-size",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Hosts scanned in parallel per async batch (default: 20). "
            "Increase for faster LAN scans; decrease on slow links."
        ),
    )
    p.add_argument(
        "--probe-delay",
        type=float,
        default=None,
        metavar="SECS",
        help="Fixed delay before each TCP probe (default: 0).",
    )
    p.add_argument(
        "--probe-jitter",
        type=float,
        default=None,
        metavar="SECS",
        help="Random additional delay before each TCP probe (default: 0).",
    )
    p.add_argument(
        "--max-results",
        type=int,
        default=None,
        metavar="N",
        help="Abort if more than N open-port results are accumulated (default: 100000).",
    )
    p.add_argument(
        "--no-nmap",
        action="store_true",
        default=None,
        help="Skip Nmap service/version enrichment",
    )
    p.add_argument(
        "--nmap-os-detect",
        action="store_true",
        default=None,
        help="Enable Nmap OS detection (-O). Requires root/CAP_NET_RAW on most systems.",
    )
    p.add_argument(
        "--nmap-timing",
        type=int,
        choices=range(0, 6),
        default=None,
        metavar="{0-5}",
        help="Nmap timing template 0=slowest to 5=fastest (default: 4)",
    )
    p.add_argument(
        "--nmap-timeout",
        type=int,
        default=None,
        metavar="SECS",
        help="Timeout for each Nmap enrichment chunk (default: 120)",
    )
    p.add_argument(
        "--nmap-discovery-timeout",
        type=int,
        default=None,
        metavar="SECS",
        help="Timeout for the Nmap discovery booster (default: 15)",
    )
    p.add_argument(
        "--cve-db",
        default=None,
        metavar="PATH",
        help="Path to CVE CSV database (default: config/cve_db.csv)",
    )
    p.add_argument(
        "--output-dir",
        default=None,
        metavar="DIR",
        help="Directory for report files (default: reports/)",
    )
    p.add_argument(
        "--report-prefix",
        default=None,
        metavar="NAME",
        help="Filename prefix for generated reports (default: netscope)",
    )
    p.add_argument(
        "--formats",
        nargs="+",
        choices=["html", "json", "csv"],
        default=None,
        help="Report formats to generate (default: html json csv)",
    )
    p.add_argument(
        "--diff",
        default=None,
        metavar="REPORT.json",
        help="Compare the new scan JSON report against a previous NetScope JSON report.",
    )
    p.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    p.add_argument(
        "--config",
        default="config/settings.yaml",
        metavar="FILE",
        help="YAML config file path (optional; CLI args take precedence)",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="TARGET",
        help="Exclude an IP, hostname, or CIDR from the scan. Repeatable.",
    )
    p.add_argument(
        "--authorize-scan",
        action="store_true",
        default=None,
        help="Acknowledge you are authorized to scan the requested target.",
    )
    p.add_argument(
        "--allow-public-targets",
        action="store_true",
        default=None,
        help="Permit public Internet targets. Requires --authorize-scan.",
    )
    return p


def _ports_from_config(config: ScanConfig) -> str | list[int]:
    return config.ports if config.ports else COMMON_PORTS


def apply_cli_overrides(config: ScanConfig, args: argparse.Namespace) -> ScanConfig:
    """
    Merge explicit CLI arguments over a loaded ScanConfig.

    argparse defaults are intentionally None for configurable options, so only
    values the user supplied on the command line override YAML/env/defaults.
    """
    merged = replace(config)
    if args.target is not None:
        merged.target = args.target
    if args.ports is not None:
        merged.ports = args.ports
    if args.timeout is not None:
        merged.timeout = args.timeout
    if args.concurrency is not None:
        merged.concurrency = args.concurrency
    if args.batch_size is not None:
        merged.host_batch_size = args.batch_size
    if args.probe_delay is not None:
        merged.probe_delay = args.probe_delay
    if args.probe_jitter is not None:
        merged.probe_jitter = args.probe_jitter
    if args.max_results is not None:
        merged.max_results = args.max_results
    if args.no_nmap is True:
        merged.use_nmap = False
    if args.nmap_os_detect is not None:
        merged.nmap_os_detect = args.nmap_os_detect
    if args.nmap_timing is not None:
        merged.nmap_timing = args.nmap_timing
    if args.nmap_timeout is not None:
        merged.nmap_timeout = args.nmap_timeout
    if args.nmap_discovery_timeout is not None:
        merged.nmap_discovery_timeout = args.nmap_discovery_timeout
    if args.cve_db is not None:
        merged.cve_db_path = args.cve_db
    if args.output_dir is not None:
        merged.output_dir = args.output_dir
    if args.report_prefix is not None:
        merged.report_prefix = args.report_prefix
    if args.formats is not None:
        merged.report_formats = args.formats
    if args.log_level is not None:
        merged.log_level = args.log_level
    if args.exclude is not None:
        merged.exclude_hosts = args.exclude
    if args.authorize_scan is not None:
        merged.authorized_scan = args.authorize_scan
    if args.allow_public_targets is not None:
        merged.allow_public_targets = args.allow_public_targets
    return merged


def validate_config_path(path: str) -> None:
    p = Path(path)
    if p.exists() and p.suffix.lower() not in {".yaml", ".yml"}:
        raise ValueError("Config file must be a .yaml or .yml file.")


def expand_excluded_hosts(exclude_specs: list[str]) -> list[str]:
    excluded: set[str] = set()
    for spec in exclude_specs:
        try:
            excluded.update(validate_target(spec))
        except ValueError as exc:
            raise ValueError(f"Invalid --exclude target '{spec}': {exc}") from exc
    return sorted(excluded, key=lambda host: tuple(int(part) for part in host.split(".")))


def validate_scan_safety(
    hosts: list[str],
    *,
    authorized_scan: bool,
    allow_public_targets: bool,
) -> None:
    public_hosts = []
    blocked_hosts = []
    for host in hosts:
        ip = ipaddress.ip_address(host)
        if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            blocked_hosts.append(host)
        elif not (ip.is_private or ip.is_loopback or ip.is_link_local):
            public_hosts.append(host)

    if blocked_hosts:
        sample = ", ".join(blocked_hosts[:5])
        raise ValueError(f"Refusing to scan unsupported special-use hosts: {sample}")
    if public_hosts and not (authorized_scan and allow_public_targets):
        sample = ", ".join(public_hosts[:5])
        raise ValueError(
            "Public targets require --authorize-scan and --allow-public-targets "
            f"(examples: {sample})."
        )


def config_file_hash(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def _run(args: argparse.Namespace, config: ScanConfig) -> int:
    # Resolve port list
    ports_spec = _ports_from_config(config)
    if ports_spec == "common":
        ports = COMMON_PORTS
    elif ports_spec == "top1000":
        ports = TOP_1000_PORTS
    elif ports_spec == "all":
        ports = ALL_PORTS
    elif isinstance(ports_spec, list):
        ports = ports_spec
    else:
        try:
            ports = validate_ports(str(ports_spec))
        except ValueError as exc:
            logger.error("Invalid port specification: %s", exc)
            return 2

    # Validate target early for a clean error message
    if not config.target:
        logger.error("Invalid target: target is required. Use -t/--target or set target in YAML.")
        return 2
    try:
        hosts = validate_target(config.target)
        excluded_hosts = expand_excluded_hosts(config.exclude_hosts)
        remaining_hosts = [host for host in hosts if host not in set(excluded_hosts)]
        if not remaining_hosts:
            logger.error("Invalid target: all hosts were excluded.")
            return 2
        validate_scan_safety(
            remaining_hosts,
            authorized_scan=config.authorized_scan,
            allow_public_targets=config.allow_public_targets,
        )
    except ValueError as exc:
        logger.error("Invalid target: %s", exc)
        return 2

    command = " ".join(sys.argv)

    # DESIGN-4: pass host_batch_size through; use scanner as context manager
    # so the shared ThreadPoolExecutor is always shut down cleanly on exit,
    # including on KeyboardInterrupt.
    with NetScopeScanner(
        target=config.target,
        ports=ports,
        timeout=config.timeout,
        concurrency=config.concurrency,
        use_nmap=config.use_nmap,
        nmap_timing=config.nmap_timing,
        nmap_os_detect=config.nmap_os_detect,
        nmap_timeout=config.nmap_timeout,
        nmap_discovery_timeout=config.nmap_discovery_timeout,
        cve_db_path=config.cve_db_path,
        excluded_hosts=excluded_hosts,
        probe_delay=config.probe_delay,
        probe_jitter=config.probe_jitter,
        max_results=config.max_results,
        scan_metadata={
            "command": command,
            "config_path": str(Path(args.config)),
            "config_sha256": config_file_hash(args.config),
            "authorized_scan": str(config.authorized_scan),
            "allow_public_targets": str(config.allow_public_targets),
        },
        host_batch_size=config.host_batch_size,
    ) as scanner:

        if args.discover:
            return await scanner.run_discovery()

        if args.discover_scan:
            active_hosts = await scanner.discover_hosts()
            if not active_hosts:
                logger.warning("Discovery found no active hosts; skipping port scan.")
                return 0
            logger.info("Discovery found %d active hosts; scanning discovered hosts only.", len(active_hosts))
            scanner.hosts = active_hosts

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
        print(f"  !  {', '.join(summary.high_risk_hosts)}")
    print("=" * 60 + "\n")

    # Export reports
    paths = export_all(
        summary,
        output_dir=config.output_dir,
        prefix=config.report_prefix,
        formats=config.report_formats,
    )
    for fmt, path in paths.items():
        logger.info("Report saved: %s -> %s", fmt.upper(), path)

    if args.diff:
        json_path = paths.get("json")
        if not json_path:
            logger.warning("--diff requires JSON output; add 'json' to --formats.")
        else:
            diff = diff_reports(args.diff, json_path)
            diff_path = str(Path(json_path).with_suffix(".diff.json"))
            write_diff_json(diff, diff_path)
            logger.info("Diff report saved: %s", diff_path)

    return 0


def main() -> None:
    print(BANNER.format(version=__version__))
    parser = build_parser()
    args = parser.parse_args()

    try:
        validate_config_path(args.config)
    except ValueError as exc:
        parser.error(str(exc))

    config = apply_cli_overrides(ScanConfig.load(args.config), args)
    setup_logging(level=config.log_level)

    try:
        exit_code = asyncio.run(_run(args, config))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        exit_code = 130
    except Exception as exc:
        logging.getLogger(__name__).critical("Fatal error: %s", exc, exc_info=True)
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
