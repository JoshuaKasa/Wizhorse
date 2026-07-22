from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from wizhorse import config
from wizhorse.daemon.cases import SAMPLES_DIR, get_sample_path
from wizhorse.daemon.scheduler import scheduler
from wizhorse.schemas.cases import Case
from wizhorse.schemas.ghidra import (
    ApiCallerInfo,
    CrossReference,
    DecompiledFunction,
    FunctionInfo,
    ImportResult,
    StringInfo,
)
from wizhorse.workers.triage import run_triage

PROJECT_NAME = "wizhorse"
PROGRAM_NAME = "sample.bin"
SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra_scripts"


class GhidraWorker:
    def import_and_analyze(self, case: Case) -> ImportResult:
        sample_path = get_sample_path(case)
        if not sample_path.is_file():
            raise FileNotFoundError(f"stored sample is missing for case_id: {case.case_id}")

        marker_path = _analysis_marker(case)
        project_dir = _project_dir(case)
        if marker_path.is_file():
            return ImportResult(
                case_id=case.case_id,
                sample_sha256=case.sample_sha256,
                project_dir=str(project_dir),
                program_name=PROGRAM_NAME,
                analyzed=True,
                skipped=True,
                warnings=[],
            )

        project_dir.mkdir(parents=True, exist_ok=True)
        output_path = _temp_json_path(project_dir)
        managed_analysis = _managed_import_settings(case)
        args = [
            str(project_dir),
            PROJECT_NAME,
            "-import",
            str(sample_path.resolve()),
            "-overwrite",
        ]
        if managed_analysis is not None:
            args.extend(
                [
                    "-analysisTimeoutPerFile",
                    str(managed_analysis["analysis_timeout_per_file_seconds"]),
                ]
            )
        args.extend(
            [
                "-scriptPath",
                str(SCRIPT_DIR),
                "-postScript",
                "wh_import_result.java",
                str(output_path),
            ]
        )
        self._run_headless(
            case=case,
            operation="import",
            project_dir=project_dir,
            args=args,
            timeout_seconds=config.ghidra_import_timeout_seconds(),
        )
        payload = _read_json(output_path)
        warnings = list(payload.get("warnings", []))
        if managed_analysis is not None:
            warnings.append(
                "managed sample detected by triage; capped Ghidra auto-analysis "
                f"at {managed_analysis['analysis_timeout_per_file_seconds']}s per file"
            )
        result = ImportResult.model_validate(
            {
                "case_id": case.case_id,
                "sample_sha256": case.sample_sha256,
                "project_dir": str(project_dir),
                "program_name": payload.get("program_name", PROGRAM_NAME),
                "analyzed": bool(payload.get("analyzed", True)),
                "skipped": False,
                "warnings": warnings,
            }
        )
        marker_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        return result

    def list_functions(self, case: Case, sort_by: str = "address") -> list[FunctionInfo]:
        self._ensure_analyzed(case)
        output_path = _temp_json_path(_project_dir(case))
        self._run_project_script(
            case,
            "wh_list_functions.java",
            [str(output_path)],
            config.ghidra_query_timeout_seconds(),
        )
        functions = TypeAdapter(list[FunctionInfo]).validate_python(_read_json(output_path))
        return _sort_functions(functions, sort_by)

    def list_strings(self, case: Case) -> list[StringInfo]:
        self._ensure_analyzed(case)
        output_path = _temp_json_path(_project_dir(case))
        self._run_project_script(
            case,
            "wh_list_strings.java",
            [str(output_path)],
            config.ghidra_query_timeout_seconds(),
        )
        return TypeAdapter(list[StringInfo]).validate_python(_read_json(output_path))

    def find_api_callers(self, case: Case, api_name: str) -> list[ApiCallerInfo]:
        if not isinstance(api_name, str) or not api_name.strip():
            raise ValueError("api_name must be a non-empty string")

        self._ensure_analyzed(case)
        output_path = _temp_json_path(_project_dir(case))
        self._run_project_script(
            case,
            "wh_find_api_callers.java",
            [str(output_path), api_name.strip()],
            config.ghidra_query_timeout_seconds(),
        )
        return TypeAdapter(list[ApiCallerInfo]).validate_python(_read_json(output_path))

    def decompile_function(self, case: Case, address: str) -> DecompiledFunction:
        if not isinstance(address, str) or not address.strip():
            raise ValueError("address must be a non-empty string")

        self._ensure_analyzed(case)
        output_path = _temp_json_path(_project_dir(case))
        self._run_project_script(
            case,
            "wh_decompile_function.java",
            [str(output_path), address.strip()],
            config.ghidra_decompile_timeout_seconds(),
        )
        return DecompiledFunction.model_validate(_read_json(output_path))

    def get_xrefs(self, case: Case, address: str) -> list[CrossReference]:
        if not isinstance(address, str) or not address.strip():
            raise ValueError("address must be a non-empty string")

        self._ensure_analyzed(case)
        output_path = _temp_json_path(_project_dir(case))
        self._run_project_script(
            case,
            "wh_get_xrefs.java",
            [str(output_path), address.strip()],
            config.ghidra_query_timeout_seconds(),
        )
        return TypeAdapter(list[CrossReference]).validate_python(_read_json(output_path))

    def _ensure_analyzed(self, case: Case) -> None:
        if not _analysis_marker(case).is_file():
            self.import_and_analyze(case)

    def _run_project_script(
        self,
        case: Case,
        script_name: str,
        script_args: list[str],
        timeout_seconds: int,
    ) -> None:
        project_dir = _project_dir_from_output(script_args[0])
        args = [
            str(project_dir),
            PROJECT_NAME,
            "-process",
            PROGRAM_NAME,
            "-noanalysis",
            "-readOnly",
            "-scriptPath",
            str(SCRIPT_DIR),
            "-postScript",
            script_name,
            *script_args,
        ]
        self._run_headless(
            case=case,
            operation=script_name.removesuffix(".java"),
            project_dir=project_dir,
            args=args,
            timeout_seconds=timeout_seconds,
        )

    def _run_headless(
        self,
        *,
        case: Case,
        operation: str,
        project_dir: Path,
        args: list[str],
        timeout_seconds: int,
    ) -> None:
        analyze_headless = config.analyze_headless_path()
        if analyze_headless is None:
            raise FileNotFoundError(
                "Ghidra is not configured. Set GHIDRA_INSTALL_DIR to your Ghidra installation directory."
            )
        if not analyze_headless.is_file():
            raise FileNotFoundError(f"Ghidra analyzeHeadless.bat not found: {analyze_headless}")

        env = _build_headless_env(project_dir)

        command = ["cmd.exe", "/c", str(analyze_headless), *args]
        scheduler.run_headless(
            case_id=case.case_id,
            operation=operation,
            project_dir=project_dir,
            command=command,
            env=env,
            timeout_seconds=timeout_seconds,
        )


def _sample_dir(case: Case) -> Path:
    return SAMPLES_DIR / case.sample_sha256


def _project_dir(case: Case) -> Path:
    return _sample_dir(case) / "ghidra_project"


def _analysis_marker(case: Case) -> Path:
    return _project_dir(case) / ".wizhorse_analysis_done.json"


def _temp_json_path(project_dir: Path) -> Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        delete=False,
        dir=project_dir,
        prefix="wizhorse_",
        suffix=".json",
    )
    handle.close()
    return Path(handle.name)


def _project_dir_from_output(output_path: str) -> Path:
    return Path(output_path).resolve().parent


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Ghidra script did not produce valid JSON at {path}") from exc


def _sort_functions(functions: list[FunctionInfo], sort_by: str) -> list[FunctionInfo]:
    if sort_by == "address":
        return sorted(functions, key=lambda function: _address_sort_key(function.address))
    if sort_by == "size":
        return sorted(functions, key=lambda function: function.size, reverse=True)
    if sort_by == "instruction_count":
        return sorted(
            functions,
            key=lambda function: function.instruction_count
            if function.instruction_count is not None
            else -1,
            reverse=True,
        )
    raise ValueError("sort_by must be one of address, size, instruction_count")


def _address_sort_key(address: str) -> tuple[int, str]:
    try:
        return (0, f"{int(address, 16):016x}")
    except ValueError:
        return (1, address)


def _managed_import_settings(case: Case) -> dict[str, int] | None:
    if not config.ghidra_fast_managed_import_enabled():
        return None

    triage = _load_or_create_triage(case)
    if not bool(triage.get("managed")):
        return None

    return {
        "analysis_timeout_per_file_seconds": max(
            1, config.ghidra_managed_analysis_timeout_per_file_seconds()
        )
    }


def _load_or_create_triage(case: Case) -> dict[str, Any]:
    triage_path = _sample_dir(case) / "static_triage.json"
    if triage_path.is_file():
        try:
            triage = _read_json(triage_path)
            if "managed" in triage:
                return triage
        except RuntimeError:
            pass
    return run_triage(case)


def _build_headless_env(project_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    project_dir = project_dir.resolve()

    resolved_java_home = config.java_home()
    if resolved_java_home is not None and resolved_java_home.exists():
        env["JAVA_HOME"] = str(resolved_java_home)

    java_home = env.get("JAVA_HOME")
    if java_home:
        java_bin = Path(java_home) / "bin"
        current_path = env.get("PATH", "")
        path_parts = [part for part in current_path.split(os.pathsep) if part]
        if str(java_bin) not in path_parts:
            env["PATH"] = os.pathsep.join([str(java_bin), *path_parts]) if path_parts else str(java_bin)

    ghidra_env_root = project_dir / ".ghidra_env"
    roaming_dir = ghidra_env_root / "Roaming"
    local_dir = ghidra_env_root / "Local"
    profile_dir = ghidra_env_root / "Profile"
    temp_dir = ghidra_env_root / "Temp"
    for path in (roaming_dir, local_dir, profile_dir, temp_dir):
        path.mkdir(parents=True, exist_ok=True)

    # Use a project-local writable profile for headless Ghidra so tests and
    # restricted environments don't depend on inherited user-profile paths.
    env["APPDATA"] = str(roaming_dir)
    env["LOCALAPPDATA"] = str(local_dir)
    env["USERPROFILE"] = str(profile_dir)
    env["HOME"] = str(profile_dir)
    env["TEMP"] = str(temp_dir)
    env["TMP"] = str(temp_dir)

    return env
