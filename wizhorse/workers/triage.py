from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from wizhorse.daemon.cases import SAMPLES_DIR, get_sample_path
from wizhorse.schemas.cases import Case


def run_triage(case: Case) -> dict:
    sample_path = get_sample_path(case)
    data = sample_path.read_bytes()
    format_details = _detect_format_details(data)
    file_format = format_details["format"]
    entropy = _shannon_entropy(data)
    warnings = []
    if entropy > 7.0:
        warnings.append("high entropy")

    result = {
        "case_id": case.case_id,
        "format": file_format,
        "file_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": entropy,
        "warnings": warnings,
        **format_details,
    }
    _triage_path(case).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _detect_format_details(data: bytes) -> dict:
    if data.startswith(b"\x7fELF"):
        return {"format": "ELF", "managed": False}
    if data.startswith(b"MZ"):
        return _detect_pe_details(data)
    return {"format": "other", "managed": False}


def _detect_pe_details(data: bytes) -> dict:
    try:
        import pefile
    except ImportError:
        return {"format": "unknown", "managed": False}

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception:
        return {"format": "unknown", "managed": False}

    managed = False
    managed_reasons: list[str] = []

    try:
        data_directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(data_directories) > 14:
            clr_directory = data_directories[14]
            if getattr(clr_directory, "VirtualAddress", 0):
                managed = True
                managed_reasons.append("clr_header")
    except Exception:
        pass

    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imports = {
            entry.dll.decode(errors="ignore").lower()
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            if getattr(entry, "dll", None)
        }
        if "mscoree.dll" in imports:
            managed = True
            managed_reasons.append("mscoree_import")
    except Exception:
        pass

    details = {"format": "PE", "managed": managed}
    if managed_reasons:
        details["managed_reasons"] = managed_reasons
    return details


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    data_length = len(data)
    counts = Counter(data)
    return -sum(
        (count / data_length) * math.log2(count / data_length)
        for count in counts.values()
    )


def _triage_path(case: Case) -> Path:
    sample_dir = SAMPLES_DIR / case.sample_sha256
    sample_dir.mkdir(parents=True, exist_ok=True)
    return sample_dir / "static_triage.json"
