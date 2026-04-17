"""
NetScope Configuration Management
Loads settings from config/settings.yaml (or environment variables).
Falls back to sensible defaults if the file is missing.

Phase 2 — Design fixes applied here:
  DESIGN-3  YAML / env-var load order corrected.
            Old order: defaults → env vars → YAML  (YAML silently overwrote env vars)
            New order: defaults → YAML → env vars  (env vars always win, as documented)
  DESIGN-4  host_batch_size is now a first-class field on ScanConfig and is forwarded
            to NetScopeScanner via main.py.
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Common port sets
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# ScanConfig dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    # Target
    target: str = ""
    ports: List[int] = field(default_factory=lambda: COMMON_PORTS.copy())

    # Timing
    timeout: float = 1.5
    concurrency: int = 500
    # DESIGN-4: host_batch_size is now explicit in the config schema.
    # Previously it was a magic number 20 buried in NetScopeScanner.run().
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

    # ---------------------------------------------------------------------------
    # DESIGN-3 FIX: corrected load-order factory methods
    #
    # Old implementation:
    #   from_yaml() called from_env() first, then applied YAML on top.
    #   Result: YAML values silently overwrote env vars.
    #   Example: NETSCOPE_TIMEOUT=5 in shell but timeout: 1.5 in YAML → got 1.5
    #
    # New implementation — three separate, composable steps:
    #   1. _from_defaults()  — pure dataclass defaults (source of truth)
    #   2. _apply_yaml()     — overlay YAML on top of defaults
    #   3. _apply_env()      — overlay env vars on top of everything (always wins)
    #
    # Public API:
    #   ScanConfig.load(yaml_path)  — full stack: defaults → YAML → env
    #   ScanConfig.from_env()       — defaults → env only (no YAML)
    #   ScanConfig.from_yaml(path)  — same as load() for backwards compat
    # ---------------------------------------------------------------------------

    @classmethod
    def _from_defaults(cls) -> "ScanConfig":
        """Return a config object populated only with dataclass defaults."""
        return cls()

    def _apply_yaml(self, path: str) -> "ScanConfig":
        """
        Overlay values from a YAML file onto self.
        Unknown keys are ignored; missing keys leave self unchanged.
        Returns self for chaining.
        """
        p = Path(path)
        if not p.exists():
            logger.debug("Settings file '%s' not found; using defaults.", path)
            return self
        try:
            import yaml  # type: ignore
            with p.open() as f:
                data = yaml.safe_load(f) or {}
            for key, val in data.items():
                if hasattr(self, key):
                    setattr(self, key, val)
                else:
                    logger.debug("Unknown config key '%s' in '%s' — ignored.", key, path)
        except ImportError:
            logger.warning("PyYAML not installed; ignoring '%s'.", path)
        except Exception as exc:
            logger.warning("Could not parse '%s': %s", path, exc)
        return self

    def _apply_env(self) -> "ScanConfig":
        """
        Overlay environment variables onto self.
        Only set env vars win; unset vars leave self unchanged.
        Returns self for chaining.
        """
        def _get(key: str) -> Optional[str]:
            return os.environ.get(key)

        if (v := _get("NETSCOPE_TIMEOUT"))      is not None: self.timeout        = float(v)
        if (v := _get("NETSCOPE_CONCURRENCY"))  is not None: self.concurrency    = int(v)
        if (v := _get("NETSCOPE_BATCH_SIZE"))   is not None: self.host_batch_size = int(v)
        if (v := _get("NETSCOPE_USE_NMAP"))     is not None: self.use_nmap       = v not in ("0", "false", "no")
        if (v := _get("NETSCOPE_NMAP_TIMING"))  is not None: self.nmap_timing    = int(v)
        if (v := _get("NETSCOPE_CVE_DB"))       is not None: self.cve_db_path    = v
        if (v := _get("NETSCOPE_SHODAN_KEY"))   is not None: self.shodan_api_key = v
        if (v := _get("NETSCOPE_OUTPUT_DIR"))   is not None: self.output_dir     = v
        if (v := _get("NETSCOPE_LOG_LEVEL"))    is not None: self.log_level      = v
        return self

    # ------------------------------------------------------------------
    # Public factory methods
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, yaml_path: str = "config/settings.yaml") -> "ScanConfig":
        """
        Canonical loader.  Correct precedence: defaults → YAML → env vars.
        Env vars always win over YAML; YAML wins over built-in defaults.
        """
        return cls._from_defaults()._apply_yaml(yaml_path)._apply_env()

    @classmethod
    def from_env(cls) -> "ScanConfig":
        """Defaults overlaid with env vars only (no YAML)."""
        return cls._from_defaults()._apply_env()

    @classmethod
    def from_yaml(cls, path: str = "config/settings.yaml") -> "ScanConfig":
        """
        Backwards-compatible alias for load().
        Previously this method had an inverted precedence order (YAML > env);
        that bug is now fixed — env vars always take precedence.
        """
        return cls.load(path)