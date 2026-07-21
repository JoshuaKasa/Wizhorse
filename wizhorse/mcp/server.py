from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from wizhorse.daemon import cases, evidence, policy
from wizhorse.reports.generator import generate_report as generate_case_report
from wizhorse.schemas.evidence import Finding
from wizhorse.workers.capa import run_capa as run_capa_worker
from wizhorse.workers.ghidra import GhidraWorker
from wizhorse.workers.triage import run_triage
from wizhorse.workers.yara import run_yara as run_yara_worker

mcp = FastMCP("wizhorse")
ghidra_worker = GhidraWorker()


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
def list_functions(case_id: str) -> dict:
    """List functions discovered in the case's Ghidra project."""
    case = _lookup_case(case_id)
    if isinstance(case, dict):
        return case
    if policy.check("list_functions", {"case_id": case.case_id}) == "DENY":
        return _error("list_functions denied by policy: case or stored sample is unavailable")

    try:
        functions = ghidra_worker.list_functions(case)
    except (FileNotFoundError, RuntimeError, TimeoutError, OSError, ValidationError) as exc:
        return _error(str(exc))
    return {"ok": True, "functions": [function.model_dump() for function in functions]}


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
