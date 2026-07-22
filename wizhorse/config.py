from __future__ import annotations

import os
from pathlib import Path

def ghidra_install_dir() -> Path | None:
    raw_value = os.getenv("GHIDRA_INSTALL_DIR")
    if not raw_value:
        return None
    return Path(raw_value).expanduser()


def analyze_headless_path() -> Path | None:
    install_dir = ghidra_install_dir()
    if install_dir is None:
        return None
    return install_dir / "support" / "analyzeHeadless.bat"


def java_home() -> Path | None:
    raw_value = os.getenv("JAVA_HOME")
    if not raw_value:
        return None
    return Path(raw_value).expanduser()


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


def capa_signatures_path() -> Path | None:
    raw_value = os.getenv("WIZHORSE_CAPA_SIGNATURES_PATH")
    if raw_value:
        return Path(raw_value).expanduser()

    default_signatures_dir = Path(__file__).resolve().parent.parent / "capa-src" / "sigs"
    if default_signatures_dir.exists():
        return default_signatures_dir
    return None


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
