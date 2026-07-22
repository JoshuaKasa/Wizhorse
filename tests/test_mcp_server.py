from __future__ import annotations

import json
import shutil
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from wizhorse import config
from wizhorse.daemon import cases, evidence
from wizhorse.daemon.scheduler import GhidraScheduler
from wizhorse.mcp.server import get_capa_locations, record_finding
from wizhorse.reports.generator import generate_report
from wizhorse.schemas.evidence import Finding
from wizhorse.workers.capa import run_capa
from wizhorse.workers import capa as capa_worker
from wizhorse.workers.ghidra import _build_headless_env
from wizhorse.workers.triage import run_triage
from wizhorse.workers.yara import run_yara


def _content_as_json(result) -> dict:
    assert result.content, "tool response did not include content"
    text = result.content[0].text
    return json.loads(text)


@pytest.mark.anyio
async def test_mcp_static_triage_workflow(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / "synthetic.bin"
    sample_path.write_bytes(b"MZ" + bytes(range(64)) + b"\x00" * 32)
    monkeypatch.setenv("WIZHORSE_ALLOWED_ROOTS", str(tmp_path))

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "wizhorse.mcp.server"],
        env={"WIZHORSE_ALLOWED_ROOTS": str(tmp_path)},
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            create_result = _content_as_json(
                await session.call_tool("create_case", {"path": str(sample_path)})
            )
            assert create_result["ok"] is True
            case = create_result["case"]
            assert case["case_id"]
            assert case["sample_sha256"]
            assert case["original_name"] == "synthetic.bin"

            triage_result = _content_as_json(
                await session.call_tool(
                    "run_static_triage",
                    {"case_id": case["case_id"]},
                )
            )
            assert triage_result["ok"] is True
            triage = triage_result["triage"]
            assert triage["case_id"] == case["case_id"]
            assert triage["sha256"] == case["sample_sha256"]
            assert triage["file_size"] == sample_path.stat().st_size
            assert triage["format"] in {"PE", "ELF", "other", "unknown"}
            assert isinstance(triage["entropy"], float)
            assert isinstance(triage["warnings"], list)

            finding = {
                "claim": "Synthetic sample was statically triaged without execution.",
                "status": "supported",
                "confidence": 0.9,
                "evidence": [
                    {
                        "source": "run_static_triage",
                        "artifact_id": case["sample_sha256"],
                        "function_address": None,
                        "observation": "Triage returned file size, hash, format, and entropy.",
                    }
                ],
                "limitations": ["Synthetic test sample is not a real malware specimen."],
            }
            finding_result = _content_as_json(
                await session.call_tool(
                    "record_finding",
                    {"case_id": case["case_id"], "finding": finding},
                )
            )
            assert finding_result["ok"] is True
            assert finding_result["finding_id"]

            shorthand_result = _content_as_json(
                await session.call_tool(
                    "record_finding",
                    {
                        "case_id": case["case_id"],
                        "finding": {
                            "claim": "string confidence shorthand should be accepted",
                            "status": "supported",
                            "confidence": "high",
                            "evidence": [
                                {
                                    "type": "test",
                                    "observation": "string confidence and type alias fixture",
                                }
                            ],
                            "limitations": [],
                        },
                    },
                )
            )
            assert shorthand_result["ok"] is True
            assert shorthand_result["finding_id"]

            invalid_result = _content_as_json(
                await session.call_tool(
                    "record_finding",
                    {
                        "case_id": case["case_id"],
                        "finding": {
                            "claim": "unknown confidence label should be rejected",
                            "status": "supported",
                            "confidence": "not-a-real-value",
                            "evidence": [
                                {
                                    "source": "test",
                                    "observation": "invalid confidence fixture",
                                }
                            ],
                            "limitations": [],
                        },
                    },
                )
            )
            assert invalid_result["ok"] is False
            assert "confidence" in invalid_result["error"]
            assert "low, medium, high" in invalid_result["error"]
            assert "ValidationError" not in invalid_result["error"]
            assert "pydantic" not in invalid_result["error"].lower()


def test_scheduler_timeout_kills_hung_subprocess_and_cleans_lock(tmp_path):
    project_dir = tmp_path / "ghidra_project"
    project_dir.mkdir()
    lock_file = project_dir / "wizhorse.lock"
    lock_file.write_text("stale", encoding="utf-8")
    scheduler = GhidraScheduler()

    with pytest.raises(TimeoutError) as exc_info:
        scheduler.run_headless(
            case_id="case-timeout",
            operation="decompile",
            project_dir=project_dir,
            command=[sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=0.2,
        )

    assert "case-timeout" in str(exc_info.value)
    assert "decompile" in str(exc_info.value)
    assert not lock_file.exists()


def test_capa_and_yara_workers_return_schema_shape(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / "synthetic.bin"
    sample_path.write_bytes(b"MZ" + b"\x00" * 128)
    case = cases.create_case(str(sample_path))

    capa_result = run_capa(case)
    assert capa_result.case_id == case.case_id
    assert capa_result.sample_sha256 == case.sample_sha256
    assert isinstance(capa_result.matches, list)
    assert isinstance(capa_result.warnings, list)

    yara_result = run_yara(case)
    assert yara_result.case_id == case.case_id
    assert yara_result.sample_sha256 == case.sample_sha256
    assert isinstance(yara_result.matches, list)
    assert isinstance(yara_result.warnings, list)


def test_run_capa_preserves_match_locations_from_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / "synthetic.bin"
    sample_path.write_bytes(b"MZ" + b"\x00" * 128)
    case = cases.create_case(str(sample_path))
    rules_path = tmp_path / "rules"
    signatures_path = tmp_path / "sigs"
    rules_path.mkdir()
    signatures_path.mkdir()

    payload = {
        "meta": {"warnings": []},
        "rules": {
            "invoke .NET assembly method": {
                "meta": {"namespace": "load-code/dotnet"},
                "matches": [
                    [
                        {"type": "dn token", "value": 100663315},
                        {
                            "success": True,
                            "locations": [],
                            "children": [
                                {
                                    "success": True,
                                    "locations": [
                                        {"type": "dn token offset", "value": [100663315, 48]}
                                    ],
                                    "children": [],
                                }
                            ],
                        },
                    ],
                    [
                        {"type": "absolute", "value": 0x10003990},
                        {
                            "success": True,
                            "locations": [{"type": "absolute", "value": 0x100039a5}],
                            "children": [],
                        },
                    ],
                ],
            }
        },
    }

    monkeypatch.setattr(capa_worker, "_resolve_capa_command", lambda: ["capa"])
    monkeypatch.setattr(capa_worker.config, "capa_rules_path", lambda: rules_path)
    monkeypatch.setattr(capa_worker.config, "capa_signatures_path", lambda: signatures_path)
    captured_command = {}

    def fake_run(*args, **kwargs):
        captured_command["args"] = args[0]
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        capa_worker.subprocess,
        "run",
        fake_run,
    )

    result = run_capa(case)

    assert captured_command["args"] == [
        "capa",
        "-r",
        str(rules_path),
        "-s",
        str(signatures_path),
        "-j",
        str(cases.get_sample_path(case)),
    ]
    assert result.matched is True
    assert result.matches[0].rule_name == "invoke .NET assembly method"
    assert result.matches[0].namespace == "load-code/dotnet"
    assert result.matches[0].locations == [
        "0x06000013",
        "0x06000013+0x30",
        "0x10003990",
        "0x100039a5",
    ]


def test_get_capa_locations_filters_saved_matches(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / "synthetic.bin"
    sample_path.write_bytes(b"MZ" + b"\x00" * 128)
    case = cases.create_case(str(sample_path))

    capa_path = cases.SAMPLES_DIR / case.sample_sha256 / "capa.json"
    capa_path.write_text(
        json.dumps(
            {
                "case_id": case.case_id,
                "sample_sha256": case.sample_sha256,
                "supported": True,
                "matched": True,
                "matches": [
                    {
                        "rule_name": "invoke .NET assembly method",
                        "namespace": "load-code/dotnet",
                        "locations": ["0x1000231c", "0x10002346"],
                    },
                    {
                        "rule_name": "load .NET assembly",
                        "namespace": "load-code/dotnet",
                        "locations": ["0x100022d8"],
                    },
                    {
                        "rule_name": "delete file",
                        "namespace": "host-interaction/file-system/delete",
                        "locations": ["0x1006642a"],
                    },
                ],
                "warnings": [],
                "error": None,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    result = get_capa_locations(case.case_id, "assembly")

    assert result["ok"] is True
    assert result["matches"] == [
        {
            "rule_name": "invoke .NET assembly method",
            "namespace": "load-code/dotnet",
            "locations": ["0x1000231c", "0x10002346"],
        },
        {
            "rule_name": "load .NET assembly",
            "namespace": "load-code/dotnet",
            "locations": ["0x100022d8"],
        },
    ]


def test_generate_report_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / "synthetic.bin"
    sample_path.write_bytes(b"MZ" + b"\x00" * 128)
    case = cases.create_case(str(sample_path))
    run_triage(case)
    finding = Finding.model_validate(
        {
            "claim": "Synthetic sample has a stored static finding.",
            "status": "supported",
            "confidence": 0.75,
            "evidence": [
                {
                    "source": "unit_test",
                    "artifact_id": case.sample_sha256,
                    "function_address": None,
                    "observation": "The finding was recorded for report generation.",
                }
            ],
            "limitations": ["Synthetic fixture only."],
        }
    )
    evidence.record_finding(case.case_id, finding)

    report = generate_report(case.case_id)

    report_path = Path(report.report_path)
    assert report_path.is_file()
    assert case.sample_sha256 in report.content
    assert "Synthetic sample has a stored static finding." in report.content


def test_finding_accepts_confidence_string_and_type_alias():
    finding = Finding.model_validate(
        {
            "claim": "String confidence and evidence type alias are normalized.",
            "status": "supported",
            "confidence": "high",
            "evidence": [
                {
                    "type": "decompile_function",
                    "artifact_id": "artifact-1",
                    "function_address": "140001000",
                    "observation": "Alias input should map to source.",
                }
            ],
            "limitations": [],
        }
    )

    assert finding.confidence == pytest.approx(0.85)
    assert finding.evidence[0].source == "decompile_function"


def test_record_finding_persists_normalized_confidence_and_type_alias(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / "synthetic.bin"
    sample_path.write_bytes(b"MZ" + b"\x00" * 128)
    case = cases.create_case(str(sample_path))

    result = evidence.record_finding(
        case.case_id,
        Finding.model_validate(
            {
                "claim": "Normalized finding is persisted.",
                "status": "supported",
                "confidence": "high",
                "evidence": [
                    {
                        "type": "decompile_function",
                        "artifact_id": case.sample_sha256,
                        "function_address": "140001000",
                        "observation": "Persisted with normalized source alias.",
                    }
                ],
                "limitations": [],
            }
        ),
    )

    assert result

    findings_dir = cases.SAMPLES_DIR / case.sample_sha256 / "findings"
    persisted_files = sorted(findings_dir.glob("*.json"))
    assert len(persisted_files) == 1
    saved_finding = json.loads(persisted_files[0].read_text(encoding="utf-8"))

    assert saved_finding["confidence"] == pytest.approx(0.85)
    assert saved_finding["evidence"][0]["source"] == "decompile_function"
    assert "type" not in saved_finding["evidence"][0]


def test_record_finding_rejects_unknown_confidence_with_clear_message(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample_path = tmp_path / "synthetic.bin"
    sample_path.write_bytes(b"MZ" + b"\x00" * 128)
    case = cases.create_case(str(sample_path))

    result = record_finding(
        case.case_id,
        {
            "claim": "Unknown confidence label should fail cleanly.",
            "status": "supported",
            "confidence": "not-a-real-value",
            "evidence": [
                {
                    "source": "test",
                    "observation": "Control fixture.",
                }
            ],
            "limitations": [],
        },
    )

    assert result["ok"] is False
    assert (
        result["error"]
        == "invalid finding: confidence must be one of low, medium, high or a number between 0 and 1, got not-a-real-value"
    )


def test_build_headless_env_sets_java_and_writable_profile_dirs(tmp_path, monkeypatch):
    project_dir = tmp_path / "ghidra_project"
    project_dir.mkdir()
    fake_java_home = tmp_path / "jdk"
    (fake_java_home / "bin").mkdir(parents=True)

    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.delenv("TEMP", raising=False)
    monkeypatch.delenv("TMP", raising=False)
    monkeypatch.setenv("JAVA_HOME", str(fake_java_home))
    monkeypatch.setenv("PATH", "")

    env = _build_headless_env(project_dir)

    assert env["JAVA_HOME"] == str(fake_java_home)
    assert env["PATH"].split(";")[0] == str(fake_java_home / "bin")
    assert env["APPDATA"] == str(project_dir / ".ghidra_env" / "Roaming")
    assert env["LOCALAPPDATA"] == str(project_dir / ".ghidra_env" / "Local")
    assert env["USERPROFILE"] == str(project_dir / ".ghidra_env" / "Profile")
    assert env["HOME"] == str(project_dir / ".ghidra_env" / "Profile")
    assert env["TEMP"] == str(project_dir / ".ghidra_env" / "Temp")
    assert env["TMP"] == str(project_dir / ".ghidra_env" / "Temp")


@pytest.mark.anyio
async def test_mcp_ghidra_workflow_on_harmless_binary(tmp_path, monkeypatch):
    analyze_headless_path = config.analyze_headless_path()
    if analyze_headless_path is None or not analyze_headless_path.is_file():
        pytest.skip("Ghidra analyzeHeadless.bat is not configured")

    monkeypatch.chdir(tmp_path)
    source_path = tmp_path / "hello.c"
    binary_path = tmp_path / "hello.exe"
    source_path.write_text(
        """
        #include <stdio.h>

        int helper(void) {
            puts("hello from wizhorse");
            return 7;
        }

        int main(void) {
            return helper();
        }
        """,
        encoding="utf-8",
    )
    _compile_harmless_binary(source_path, binary_path)
    monkeypatch.setenv("WIZHORSE_ALLOWED_ROOTS", str(tmp_path))

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "wizhorse.mcp.server"],
        env={"WIZHORSE_ALLOWED_ROOTS": str(tmp_path)},
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            create_result = _content_as_json(
                await session.call_tool("create_case", {"path": str(binary_path)})
            )
            assert create_result["ok"] is True
            case_id = create_result["case"]["case_id"]

            import_result = _content_as_json(
                await session.call_tool("import_and_analyze", {"case_id": case_id})
            )
            assert import_result["ok"] is True, import_result
            assert import_result["result"]["analyzed"] is True

            functions_result = _content_as_json(
                await session.call_tool("list_functions", {"case_id": case_id})
            )
            assert functions_result["ok"] is True
            assert functions_result["functions"]

            first_function = functions_result["functions"][0]
            decompile_result = _content_as_json(
                await session.call_tool(
                    "decompile_function",
                    {"case_id": case_id, "address": first_function["address"]},
                )
            )
            assert decompile_result["ok"] is True
            assert decompile_result["function"]["pseudocode"].strip()

            xrefs_result = _content_as_json(
                await session.call_tool(
                    "get_xrefs",
                    {"case_id": case_id, "address": first_function["address"]},
                )
            )
            assert xrefs_result["ok"] is True
            assert isinstance(xrefs_result["xrefs"], list)


def _compile_harmless_binary(source_path, binary_path) -> None:
    compilers = [
        compiler
        for compiler in (shutil.which("clang"), shutil.which("gcc"))
        if compiler is not None
    ]
    if not compilers:
        pytest.skip("no C compiler available to build harmless test binary")

    failures = []
    for compiler in compilers:
        stdout_path = binary_path.with_suffix(f".{Path(compiler).stem}.stdout.log")
        stderr_path = binary_path.with_suffix(f".{Path(compiler).stem}.stderr.log")
        with stdout_path.open("w", encoding="utf-8") as stdout_file:
            with stderr_path.open("w", encoding="utf-8") as stderr_file:
                completed = subprocess.run(
                    [compiler, str(source_path), "-o", str(binary_path)],
                    stderr=stderr_file,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    text=True,
                    timeout=60,
                )
        if completed.returncode == 0 and binary_path.is_file():
            return
        failures.append(f"{compiler} exited {completed.returncode}")

    pytest.skip("no available C compiler could build harmless test binary: " + "; ".join(failures))
