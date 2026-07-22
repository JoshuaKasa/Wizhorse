from __future__ import annotations

import json
import re
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from wizhorse.daemon import cases, evidence, policy
from wizhorse.reports.generator import generate_report as generate_case_report
from wizhorse.schemas.capa import CapaResult
from wizhorse.schemas.evidence import Finding
from wizhorse.schemas.ghidra import FunctionInfo
from wizhorse.workers.capa import run_capa as run_capa_worker
from wizhorse.workers.ghidra import GhidraWorker
from wizhorse.workers.triage import run_triage
from wizhorse.workers.yara import run_yara as run_yara_worker

mcp = FastMCP("wizhorse")
ghidra_worker = GhidraWorker()
_DOTNET_TOKEN_PATTERN = re.compile(
    r"^0x(?P<token>06[0-9a-fA-F]{6})(?:\+0x(?P<offset>[0-9a-fA-F]+))?$"
)


@mcp.tool()
def create_case(path: str) -> dict:
    """Create a static-analysis case from a local sample path."""
    if not isinstance(path, str) or not path.strip():
        return _error("path must be a non-empty string")

    source_path = path.strip()
    if policy.check("create_case", {"source_path": source_path}) == "DENY":
        return _error("create_case denied by policy: path is outside allowed roots")

    try:
        case = cases.create_case(source_path)
    except FileNotFoundError as exc:
        return _error(str(exc))
    except OSError as exc:
        return _error(f"could not create case: {exc}")

    return {
        "ok": True,
        "case": _case_summary(case),
    }


@mcp.tool()
def run_static_triage(case_id: str) -> dict:
    """Run dependency-light static triage for a known case."""
    if not isinstance(case_id, str) or not case_id.strip():
        return _error("case_id must be a non-empty string")

    try:
        case = cases.get_case(case_id.strip())
    except KeyError:
        return _error(f"unknown case_id: {case_id}")

    sample_path = cases.get_sample_path(case)
    if not sample_path.is_file():
        return _error(f"stored sample is missing for case_id: {case.case_id}")

    try:
        return {"ok": True, "triage": run_triage(case)}
    except OSError as exc:
        return _error(f"could not run static triage: {exc}")


@mcp.tool()
def record_finding(case_id: str, finding: dict[str, Any]) -> dict:
    """Record an evidence-backed finding for a known case."""
    if not isinstance(case_id, str) or not case_id.strip():
        return _error("case_id must be a non-empty string")
    if not isinstance(finding, dict):
        return _error("finding must be an object")

    try:
        cases.get_case(case_id.strip())
    except KeyError:
        return _error(f"unknown case_id: {case_id}")

    try:
        validated_finding = Finding.model_validate(finding)
    except ValidationError as exc:
        return _error(f"invalid finding: {_format_validation_errors(exc)}")

    try:
        finding_id = evidence.record_finding(case_id.strip(), validated_finding)
    except KeyError:
        return _error(f"unknown case_id: {case_id}")
    except OSError as exc:
        return _error(f"could not record finding: {exc}")

    return {"ok": True, "finding_id": finding_id}


@mcp.tool()
def run_capa(case_id: str) -> dict:
    """Run Mandiant capa against a known case."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if policy.check("run_capa", {"case_id": case.case_id}) == "DENY":
        return _error("run_capa denied by policy: case or stored sample is unavailable")

    try:
        result = run_capa_worker(case)
    except OSError as exc:
        return _error(f"could not run capa: {exc}")
    return {"ok": True, "capa": result.model_dump()}


@mcp.tool()
def get_capa_locations(case_id: str, capability_substring: str) -> dict:
    """Return stored capa match locations for capabilities matching a substring."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if not isinstance(capability_substring, str) or not capability_substring.strip():
        return _error("capability_substring must be a non-empty string")
    if policy.check("get_capa_locations", {"case_id": case.case_id}) == "DENY":
        return _error("get_capa_locations denied by policy: case or stored sample is unavailable")

    try:
        capa_result = _load_capa_result(case)
    except (FileNotFoundError, OSError, ValidationError) as exc:
        return _error(f"could not load stored capa result: {exc}")

    needle = capability_substring.strip().lower()
    matches = []
    for match in capa_result.matches:
        if needle not in match.rule_name.lower():
            continue
        matches.append(
            {
                "rule_name": match.rule_name,
                "namespace": match.namespace,
                "locations": _resolve_capa_locations(case, match.locations),
            }
        )
    return {"ok": True, "matches": matches}


@mcp.tool()
def run_yara(case_id: str) -> dict:
    """Run configured YARA rules against a known case."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if policy.check("run_yara", {"case_id": case.case_id}) == "DENY":
        return _error("run_yara denied by policy: case or stored sample is unavailable")

    try:
        result = run_yara_worker(case)
    except OSError as exc:
        return _error(f"could not run YARA: {exc}")
    return {"ok": True, "yara": result.model_dump()}


@mcp.tool()
def import_and_analyze(case_id: str) -> dict:
    """Import a quarantined sample into Ghidra and run auto-analysis."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if policy.check("import_and_analyze", {"case_id": case.case_id}) == "DENY":
        return _error("import_and_analyze denied by policy: case or stored sample is unavailable")

    try:
        return {"ok": True, "result": ghidra_worker.import_and_analyze(case).model_dump()}
    except (FileNotFoundError, RuntimeError, TimeoutError, OSError) as exc:
        return _error(str(exc))


@mcp.tool()
def list_functions(case_id: str, sort_by: str = "address") -> dict:
    """List functions discovered in the case's Ghidra project."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if policy.check("list_functions", {"case_id": case.case_id}) == "DENY":
        return _error("list_functions denied by policy: case or stored sample is unavailable")

    try:
        functions = ghidra_worker.list_functions(case, sort_by=sort_by)
    except (
        FileNotFoundError,
        RuntimeError,
        TimeoutError,
        OSError,
        ValueError,
        ValidationError,
    ) as exc:
        return _error(str(exc))
    return {"ok": True, "functions": [function.model_dump() for function in functions]}


@mcp.tool()
def list_strings(case_id: str) -> dict:
    """List defined strings and function references in the case's Ghidra project."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if policy.check("list_strings", {"case_id": case.case_id}) == "DENY":
        return _error("list_strings denied by policy: case or stored sample is unavailable")

    try:
        strings = ghidra_worker.list_strings(case)
    except (FileNotFoundError, RuntimeError, TimeoutError, OSError, ValidationError) as exc:
        return _error(str(exc))
    return {"ok": True, "strings": [string.model_dump() for string in strings]}


@mcp.tool()
def find_api_callers(case_id: str, api_name: str) -> dict:
    """Find functions that directly call an imported API by name."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if not isinstance(api_name, str) or not api_name.strip():
        return _error("api_name must be a non-empty string")
    if policy.check("find_api_callers", {"case_id": case.case_id}) == "DENY":
        return _error("find_api_callers denied by policy: case or stored sample is unavailable")

    try:
        callers = ghidra_worker.find_api_callers(case, api_name)
    except (
        FileNotFoundError,
        RuntimeError,
        TimeoutError,
        OSError,
        ValueError,
        ValidationError,
    ) as exc:
        return _error(str(exc))
    return {"ok": True, "callers": [caller.model_dump() for caller in callers]}


@mcp.tool()
def decompile_function(case_id: str, address: str) -> dict:
    """Decompile a function at or containing the requested address."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if not isinstance(address, str) or not address.strip():
        return _error("address must be a non-empty string")
    if policy.check("decompile_function", {"case_id": case.case_id}) == "DENY":
        return _error("decompile_function denied by policy: case or stored sample is unavailable")

    try:
        decompiled = ghidra_worker.decompile_function(case, address)
    except (
        FileNotFoundError,
        RuntimeError,
        TimeoutError,
        OSError,
        ValueError,
        ValidationError,
    ) as exc:
        return _error(str(exc))
    return {"ok": True, "function": decompiled.model_dump()}


@mcp.tool()
def get_xrefs(case_id: str, address: str) -> dict:
    """Get cross-references to and from the requested address."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if not isinstance(address, str) or not address.strip():
        return _error("address must be a non-empty string")
    if policy.check("get_xrefs", {"case_id": case.case_id}) == "DENY":
        return _error("get_xrefs denied by policy: case or stored sample is unavailable")

    try:
        xrefs = ghidra_worker.get_xrefs(case, address)
    except (
        FileNotFoundError,
        RuntimeError,
        TimeoutError,
        OSError,
        ValueError,
        ValidationError,
    ) as exc:
        return _error(str(exc))
    return {"ok": True, "xrefs": [xref.model_dump() for xref in xrefs]}


@mcp.tool()
def generate_report(case_id: str) -> dict:
    """Generate a Markdown technical report for a known case."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if policy.check("generate_report", {"case_id": case.case_id}) == "DENY":
        return _error("generate_report denied by policy: case or stored sample is unavailable")

    try:
        report = generate_case_report(case.case_id)
    except (KeyError, OSError, ValidationError) as exc:
        return _error(f"could not generate report: {exc}")
    return {
        "ok": True,
        "report_path": report.report_path,
        "content": report.content,
    }


def _lookup_case(case_id: str):
    if not isinstance(case_id, str) or not case_id.strip():
        return _error("case_id must be a non-empty string")
    try:
        return cases.get_case(case_id.strip())
    except KeyError:
        return _error(f"unknown case_id: {case_id}")


def _load_capa_result(case: cases.Case) -> CapaResult:
    path = cases.SAMPLES_DIR / case.sample_sha256 / "capa.json"
    if not path.is_file():
        raise FileNotFoundError(f"stored capa result is missing for case_id: {case.case_id}")
    return CapaResult.model_validate_json(path.read_text(encoding="utf-8"))


def _resolve_capa_locations(case: cases.Case, locations: list[str]) -> list[str]:
    if not locations:
        return []
    if not any(_DOTNET_TOKEN_PATTERN.match(location) for location in locations):
        return locations

    try:
        functions = ghidra_worker.list_functions(case)
    except (FileNotFoundError, RuntimeError, TimeoutError, OSError, ValidationError):
        return locations

    resolved = []
    for location in locations:
        resolved.append(_resolve_single_capa_location(location, functions))
    return resolved


def _resolve_single_capa_location(location: str, functions: list[FunctionInfo]) -> str:
    match = _DOTNET_TOKEN_PATTERN.match(location)
    if match is None:
        return location

    token_value = int(match.group("token"), 16)
    row_index = token_value & 0x00FFFFFF
    if row_index < 1 or row_index > len(functions):
        return location

    function_address = int(functions[row_index - 1].address, 16)
    offset_text = match.group("offset")
    if offset_text is not None:
        function_address += int(offset_text, 16)
    return f"0x{function_address:x}"


def _case_summary(case: cases.Case) -> dict:
    return {
        "case_id": case.case_id,
        "sample_sha256": case.sample_sha256,
        "original_name": case.original_name,
        "status": case.status,
        "created_at": case.created_at.isoformat(),
        "analysis_profile": case.analysis_profile,
    }


def _error(message: str) -> dict:
    return {"ok": False, "error": message}


def _format_validation_errors(exc: ValidationError) -> str:
    messages = [_format_validation_error(error) for error in exc.errors()]
    return "; ".join(messages)


def _format_validation_error(error: dict[str, Any]) -> str:
    field = ".".join(str(part) for part in error.get("loc", ())) or "finding"
    error_type = str(error.get("type", ""))
    value = error.get("input")

    if field == "confidence" and error_type in {"float_parsing", "float_type"}:
        return f"confidence must be a number between 0 and 1, got {_describe_value(value)}"
    if field == "confidence" and error_type in {"greater_than_equal", "less_than_equal"}:
        return f"confidence must be between 0 and 1, got {_describe_value(value)}"
    if field == "confidence" and error_type == "confidence_value":
        return str(error.get("msg", "confidence is invalid"))
    if error_type == "extra_forbidden":
        return f"{field} is not allowed"
    if error_type == "missing":
        return f"{field} is required"
    if error_type.endswith("_type"):
        return f"{field} has the wrong type, got {_describe_value(value)}"
    return f"{field}: {error.get('msg', 'invalid value')}"


def _describe_value(value: Any) -> str:
    if isinstance(value, str):
        return f"string {value!r}"
    return repr(value)


if __name__ == "__main__":
    mcp.run(transport="stdio")
