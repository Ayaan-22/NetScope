"""
NetScope Configuration Management
Loads settings from config/settings.yaml (or environment variables).
Falls back to sensible defaults if the file is missing.
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# Common port sets
COMMON_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 587, 993, 995, 1723, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 27017,
]

TOP_1000_PORTS: List[int] = list(range(1, 1025)) + [
    1433, 1521, 1723, 2049, 2181, 3000, 3306, 3389,
    4444, 4848, 5432, 5900, 6379, 6443, 7001, 8000,
    8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
    9300, 10000, 27017, 27018, 28017,
]

ALL_PORTS: List[int] = list(range(1, 65536))


@dataclass
class ScanConfig:
    # Target
    target: str = ""
    ports: List[int] = field(default_factory=lambda: COMMON_PORTS.copy())

    # Timing
    timeout: float = 1.5
    concurrency: int = 500
    host_batch_size: int = 20

    # Nmap
    use_nmap: bool = True
    nmap_timing: int = 4

    # CVE database
    cve_db_path: str = "config/cve_db.csv"

    # Shodan (optional)
    shodan_api_key: str = ""

    # Output
    output_dir: str = "reports"
    report_prefix: str = "netscope"
    report_formats: List[str] = field(default_factory=lambda: ["html", "json", "csv"])

    # Logging
    log_level: str = "INFO"
    log_dir: str = "logs"

    @classmethod
    def from_env(cls) -> "ScanConfig":
        """Override defaults from environment variables."""
        cfg = cls()
        cfg.timeout        = float(os.getenv("NETSCOPE_TIMEOUT",      cfg.timeout))
        cfg.concurrency    = int(os.getenv("NETSCOPE_CONCURRENCY",    cfg.concurrency))
        cfg.use_nmap       = os.getenv("NETSCOPE_USE_NMAP", "1") not in ("0", "false", "no")
        cfg.nmap_timing    = int(os.getenv("NETSCOPE_NMAP_TIMING",    cfg.nmap_timing))
        cfg.cve_db_path    = os.getenv("NETSCOPE_CVE_DB",             cfg.cve_db_path)
        cfg.shodan_api_key = os.getenv("NETSCOPE_SHODAN_KEY",         cfg.shodan_api_key)
        cfg.output_dir     = os.getenv("NETSCOPE_OUTPUT_DIR",         cfg.output_dir)
        cfg.log_level      = os.getenv("NETSCOPE_LOG_LEVEL",          cfg.log_level)
        return cfg

    @classmethod
    def from_yaml(cls, path: str = "config/settings.yaml") -> "ScanConfig":
        """Load from YAML, then overlay env vars."""
        cfg = cls.from_env()
        p = Path(path)
        if not p.exists():
            logger.debug("Settings file '%s' not found; using defaults.", path)
            return cfg
        try:
            import yaml  # type: ignore
            with p.open() as f:
                data = yaml.safe_load(f) or {}
            for key, val in data.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, val)
        except ImportError:
            logger.warning("PyYAML not installed; ignoring '%s'.", path)
        except Exception as exc:
            logger.warning("Could not parse '%s': %s", path, exc)
        return cfg
