from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from wizhorse.daemon import cases, evidence
from wizhorse.daemon.cases import SAMPLES_DIR
from wizhorse.schemas.report import ReportSummary

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATE_NAME = "technical.md.j2"


def generate_report(case_id: str) -> ReportSummary:
    case = cases.get_case(case_id)
    findings = evidence.get_findings(case_id)
    sample_dir = SAMPLES_DIR / case.sample_sha256
    triage = _read_optional_json(sample_dir / "static_triage.json")
    capa = _read_optional_json(sample_dir / "capa.json")
    yara = _read_optional_json(sample_dir / "yara.json")
    verdict = _derive_verdict(findings)

    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(enabled_extensions=()),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = environment.get_template(TEMPLATE_NAME)
    content = template.render(
        case=case,
        findings=findings,
        triage=triage,
        capa=capa,
        yara=yara,
        verdict=verdict,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = sample_dir / f"report_{timestamp}.md"
    report_path.write_text(content, encoding="utf-8")
    return ReportSummary(
        case_id=case.case_id,
        sample_sha256=case.sample_sha256,
        report_path=str(report_path),
        content=content,
    )


def _derive_verdict(findings: list[Any]) -> str:
    if not findings:
        return "insufficient evidence"
    highest_confidence = max(findings, key=lambda finding: finding.confidence)
    return highest_confidence.status


def _read_optional_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    return payload if isinstance(payload, dict) else {"items": payload}
