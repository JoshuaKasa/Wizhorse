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
    file_format = _detect_format(data)
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
    }
    _triage_path(case).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _detect_format(data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"MZ"):
        return _detect_pe_format(data)
    return "other"


def _detect_pe_format(data: bytes) -> str:
    try:
        import pefile
    except ImportError:
        return "unknown"

    try:
        pefile.PE(data=data, fast_load=True)
    except Exception:
        return "unknown"
    return "PE"


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
