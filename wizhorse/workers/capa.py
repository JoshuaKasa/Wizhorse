from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from wizhorse import config
from wizhorse.daemon.cases import SAMPLES_DIR, get_sample_path
from wizhorse.schemas.capa import CapaMatch, CapaResult
from wizhorse.schemas.cases import Case


def run_capa(case: Case) -> CapaResult:
    capa_path = shutil.which("capa")
    if capa_path is None:
        return _persist(
            case,
            CapaResult(
                case_id=case.case_id,
                sample_sha256=case.sample_sha256,
                supported=False,
                matched=False,
                matches=[],
                warnings=["capa not found, install from github.com/mandiant/capa"],
                error="capa not found, install from github.com/mandiant/capa",
            ),
        )

    sample_path = get_sample_path(case)
    try:
        completed = subprocess.run(
            [capa_path, "-j", str(sample_path)],
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            timeout=config.capa_timeout_seconds(),
        )
    except subprocess.TimeoutExpired:
        return _persist(
            case,
            CapaResult(
                case_id=case.case_id,
                sample_sha256=case.sample_sha256,
                supported=False,
                matched=False,
                matches=[],
                warnings=[f"capa timed out after {config.capa_timeout_seconds()}s"],
                error=f"capa timed out after {config.capa_timeout_seconds()}s",
            ),
        )

    output = completed.stdout.strip()
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip() or "capa failed"
        unsupported = _looks_unsupported(message)
        return _persist(
            case,
            CapaResult(
                case_id=case.case_id,
                sample_sha256=case.sample_sha256,
                supported=not unsupported,
                matched=False,
                matches=[],
                warnings=[_short_message(message)],
                error=_short_message(message),
            ),
        )

    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return _persist(
            case,
            CapaResult(
                case_id=case.case_id,
                sample_sha256=case.sample_sha256,
                supported=False,
                matched=False,
                matches=[],
                warnings=["capa did not return valid JSON"],
                error="capa did not return valid JSON",
            ),
        )

    matches = _extract_matches(payload)
    warnings = _extract_warnings(payload)
    if not matches:
        warnings.append(
            "capa returned no capability matches; this may be expected for unsupported or managed/.NET binaries"
        )

    return _persist(
        case,
        CapaResult(
            case_id=case.case_id,
            sample_sha256=case.sample_sha256,
            supported=True,
            matched=bool(matches),
            matches=matches,
            warnings=warnings,
            error=None,
        ),
    )


def _extract_matches(payload: dict[str, Any]) -> list[CapaMatch]:
    rules = payload.get("rules")
    if not isinstance(rules, dict):
        return []

    matches: list[CapaMatch] = []
    for rule_name, rule_payload in sorted(rules.items()):
        if not isinstance(rule_payload, dict):
            continue
        meta = rule_payload.get("meta") if isinstance(rule_payload.get("meta"), dict) else {}
        namespace = meta.get("namespace") if isinstance(meta, dict) else None
        locations = sorted(_collect_locations(rule_payload))
        matches.append(
            CapaMatch(
                rule=str(rule_name),
                namespace=str(namespace) if namespace is not None else None,
                locations=locations,
            )
        )
    return matches


def _collect_locations(value: Any) -> set[str]:
    locations: set[str] = set()
    if isinstance(value, dict):
        if "address" in value:
            locations.add(str(value["address"]))
        if "value" in value and isinstance(value["value"], str) and value["value"].startswith("0x"):
            locations.add(value["value"])
        for child in value.values():
            locations.update(_collect_locations(child))
    elif isinstance(value, list):
        for child in value:
            locations.update(_collect_locations(child))
    elif isinstance(value, str) and value.startswith("0x"):
        locations.add(value)
    return locations


def _extract_warnings(payload: dict[str, Any]) -> list[str]:
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        return []
    warnings = meta.get("warnings")
    if not isinstance(warnings, list):
        return []
    return [str(warning) for warning in warnings]


def _looks_unsupported(message: str) -> bool:
    lowered = message.lower()
    return any(
        marker in lowered
        for marker in (
            "unsupported",
            "not supported",
            "could not identify file type",
            "does not appear to be a pe",
            "no rules matched",
        )
    )


def _short_message(message: str) -> str:
    return " ".join(message.split())[:500]


def _persist(case: Case, result: CapaResult) -> CapaResult:
    path = _result_path(case)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return result


def _result_path(case: Case) -> Path:
    return SAMPLES_DIR / case.sample_sha256 / "capa.json"
