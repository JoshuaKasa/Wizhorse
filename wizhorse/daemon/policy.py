from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

PolicyDecision = Literal["ALLOW", "DENY"]
_GHIDRA_CASE_OPERATIONS = {
    "import_and_analyze",
    "list_functions",
    "decompile_function",
    "get_xrefs",
    "get_capa_locations",
    "run_capa",
    "run_yara",
    "generate_report",
}


def check(operation: str, context: dict) -> PolicyDecision:
    if operation in _GHIDRA_CASE_OPERATIONS:
        return _check_quarantined_case(context)

    if operation != "create_case":
        return "ALLOW"

    source_path = context.get("source_path")
    if not isinstance(source_path, str) or not source_path:
        return "DENY"

    try:
        source = Path(source_path).expanduser().resolve()
        allowed_roots = _allowed_roots()
    except OSError:
        return "DENY"

    if any(_is_relative_to(source, root) for root in allowed_roots):
        return "ALLOW"
    return "DENY"


def _check_quarantined_case(context: dict) -> PolicyDecision:
    try:
        from wizhorse.daemon import cases

        case_id = context.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            return "DENY"
        case = cases.get_case(case_id)
        if not cases.get_sample_path(case).is_file():
            return "DENY"
    except (KeyError, OSError):
        return "DENY"
    return "ALLOW"


def _allowed_roots() -> list[Path]:
    roots = os.getenv("WIZHORSE_ALLOWED_ROOTS")
    raw_roots = roots.split(",") if roots else [os.getcwd()]
    return [
        Path(raw_root.strip()).expanduser().resolve()
        for raw_root in raw_roots
        if raw_root.strip()
    ]


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
