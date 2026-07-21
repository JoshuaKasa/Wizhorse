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
    CrossReference,
    DecompiledFunction,
    FunctionInfo,
    ImportResult,
)

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
        args = [
            str(project_dir),
            PROJECT_NAME,
            "-import",
            str(sample_path.resolve()),
            "-overwrite",
            "-scriptPath",
            str(SCRIPT_DIR),
            "-postScript",
            "wh_import_result.java",
            str(output_path),
        ]
        self._run_headless(
            case=case,
            operation="import",
            project_dir=project_dir,
            args=args,
            timeout_seconds=config.ghidra_import_timeout_seconds(),
        )
        payload = _read_json(output_path)
        result = ImportResult.model_validate(
            {
                "case_id": case.case_id,
                "sample_sha256": case.sample_sha256,
                "project_dir": str(project_dir),
                "program_name": payload.get("program_name", PROGRAM_NAME),
                "analyzed": bool(payload.get("analyzed", True)),
                "skipped": False,
                "warnings": payload.get("warnings", []),
            }
        )
        marker_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        return result

    def list_functions(self, case: Case) -> list[FunctionInfo]:
        self._ensure_analyzed(case)
        output_path = _temp_json_path(_project_dir(case))
        self._run_project_script(
            case,
            "wh_list_functions.java",
            [str(output_path)],
            config.ghidra_query_timeout_seconds(),
        )
        return TypeAdapter(list[FunctionInfo]).validate_python(_read_json(output_path))

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
        if not analyze_headless.is_file():
            raise FileNotFoundError(f"Ghidra analyzeHeadless.bat not found: {analyze_headless}")

        env = os.environ.copy()
        resolved_java_home = config.java_home()
        if resolved_java_home.exists():
            env["JAVA_HOME"] = str(resolved_java_home)

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

