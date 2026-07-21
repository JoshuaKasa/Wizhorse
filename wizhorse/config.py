from __future__ import annotations

import os
from pathlib import Path

DEFAULT_GHIDRA_INSTALL_DIR = (
    r"C:\Users\jizos\Documents\Programming\Reverse engineering\Ghidra"
)
DEFAULT_JAVA_HOME = r"C:\Program Files\Eclipse Adoptium\jdk-21.0.10.7-hotspot"


def ghidra_install_dir() -> Path:
    return Path(os.getenv("GHIDRA_INSTALL_DIR", DEFAULT_GHIDRA_INSTALL_DIR)).expanduser()


def analyze_headless_path() -> Path:
    return ghidra_install_dir() / "support" / "analyzeHeadless.bat"


def java_home() -> Path:
    return Path(os.getenv("JAVA_HOME", DEFAULT_JAVA_HOME)).expanduser()


def ghidra_import_timeout_seconds() -> int:
    return _int_env("WIZHORSE_GHIDRA_IMPORT_TIMEOUT_SECONDS", 600)


def ghidra_fast_managed_import_enabled() -> bool:
    return _bool_env("WIZHORSE_GHIDRA_FAST_MANAGED_IMPORT_ENABLED", True)


def ghidra_managed_analysis_timeout_per_file_seconds() -> int:
    return _int_env("WIZHORSE_GHIDRA_MANAGED_ANALYSIS_TIMEOUT_PER_FILE_SECONDS", 45)


def ghidra_decompile_timeout_seconds() -> int:
    return _int_env("WIZHORSE_GHIDRA_DECOMPILE_TIMEOUT_SECONDS", 180)


def ghidra_query_timeout_seconds() -> int:
    return _int_env("WIZHORSE_GHIDRA_QUERY_TIMEOUT_SECONDS", 60)


def ghidra_max_concurrent_operations() -> int:
    return max(1, _int_env("WIZHORSE_GHIDRA_MAX_CONCURRENT_OPERATIONS", 1))


def capa_timeout_seconds() -> int:
    return _int_env("WIZHORSE_CAPA_TIMEOUT_SECONDS", 180)


def capa_rules_path() -> Path:
    default_rules_dir = Path(__file__).resolve().parent.parent / "capa-rules"
    return Path(os.getenv("WIZHORSE_CAPA_RULES_PATH", default_rules_dir)).expanduser()


def capa_signatures_path() -> Path:
    default_signatures_dir = Path(__file__).resolve().parent.parent / "capa-src" / "sigs"
    return Path(
        os.getenv("WIZHORSE_CAPA_SIGNATURES_PATH", default_signatures_dir)
    ).expanduser()


def yara_rules_dir() -> Path:
    default_rules_dir = Path(__file__).resolve().parent / "workers" / "yara_rules"
    return Path(os.getenv("WIZHORSE_YARA_RULES_DIR", default_rules_dir)).expanduser()


def _int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    lowered = raw_value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return default
