from __future__ import annotations

import json
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Any

from wizhorse import config
from wizhorse.daemon.cases import SAMPLES_DIR, get_sample_path
from wizhorse.schemas.capa import CapaMatch, CapaResult
from wizhorse.schemas.cases import Case


def run_capa(case: Case) -> CapaResult:
    capa_command = _resolve_capa_command()
    if capa_command is None:
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
    rules_path = config.capa_rules_path()
    signatures_path = config.capa_signatures_path()
    command = [
        *capa_command,
        "-r",
        str(rules_path),
    ]
    if signatures_path is not None:
        command.extend(["-s", str(signatures_path)])
    command.extend(["-j", str(sample_path)])
    try:
        completed = subprocess.run(
            command,
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
        namespace = meta.get("namespace") if isinstance(meta, dict) else ""
        locations = sorted(_collect_match_locations(rule_payload.get("matches")))
        matches.append(
            CapaMatch(
                rule_name=str(rule_name),
                namespace=str(namespace) if namespace is not None else "",
                locations=locations,
            )
        )
    return matches


def _collect_match_locations(raw_matches: Any) -> set[str]:
    locations: set[str] = set()
    if not isinstance(raw_matches, list):
        return locations

    for raw_match in raw_matches:
        if isinstance(raw_match, list) and raw_match:
            primary_location = _format_capa_location(raw_match[0])
            if primary_location is not None:
                locations.add(primary_location)
            for node in raw_match[1:]:
                locations.update(_collect_nested_locations(node))
        else:
            fallback_location = _format_capa_location(raw_match)
            if fallback_location is not None:
                locations.add(fallback_location)
    return locations


def _collect_nested_locations(value: Any) -> set[str]:
    locations: set[str] = set()
    if isinstance(value, dict):
        if isinstance(value.get("locations"), list):
            for raw_location in value["locations"]:
                formatted = _format_capa_location(raw_location)
                if formatted is not None:
                    locations.add(formatted)
        for child in value.values():
            locations.update(_collect_nested_locations(child))
    elif isinstance(value, list):
        for child in value:
            locations.update(_collect_nested_locations(child))
    return locations


def _format_capa_location(raw_location: Any) -> str | None:
    if not isinstance(raw_location, dict):
        return None

    location_type = raw_location.get("type")
    raw_value = raw_location.get("value")
    if location_type == "no address":
        return None
    if location_type == "dn token" and isinstance(raw_value, int):
        return f"0x{raw_value:08x}"
    if (
        location_type == "dn token offset"
        and isinstance(raw_value, list)
        and len(raw_value) == 2
        and all(isinstance(part, int) for part in raw_value)
    ):
        return f"0x{raw_value[0]:08x}+0x{raw_value[1]:x}"
    if location_type == "file" and isinstance(raw_value, int):
        return f"file+0x{raw_value:x}"
    if isinstance(raw_value, int):
        return f"0x{raw_value:x}"
    if isinstance(raw_value, str):
        return raw_value
    return None


def _extract_warnings(payload: dict[str, Any]) -> list[str]:
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        return []
    warnings = meta.get("warnings")
    if not isinstance(warnings, list):
        return []
    return [str(warning) for warning in warnings]


def _resolve_capa_command() -> list[str] | None:
    capa_path = shutil.which("capa")
    if capa_path is not None:
        return [capa_path]

    scripts_dir = sysconfig.get_path("scripts")
    if scripts_dir:
        candidate = Path(scripts_dir) / ("capa.exe" if sys.platform == "win32" else "capa")
        if candidate.is_file():
            return [str(candidate)]

    return [sys.executable, "-m", "capa.main"]


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
