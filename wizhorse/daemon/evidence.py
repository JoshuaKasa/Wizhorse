from __future__ import annotations

import json
import uuid
from pathlib import Path

from wizhorse.daemon.cases import SAMPLES_DIR, get_case
from wizhorse.schemas.evidence import Finding


def record_finding(case_id: str, finding: Finding) -> str:
    case = get_case(case_id)
    finding_id = uuid.uuid4().hex
    findings_dir = SAMPLES_DIR / case.sample_sha256 / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    finding_path = findings_dir / f"{finding_id}.json"
    finding_path.write_text(
        finding.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return finding_id


def get_findings(case_id: str) -> list[Finding]:
    case = get_case(case_id)
    findings_dir = SAMPLES_DIR / case.sample_sha256 / "findings"
    if not findings_dir.exists():
        return []

    findings: list[Finding] = []
    for finding_path in sorted(findings_dir.glob("*.json")):
        with finding_path.open("r", encoding="utf-8") as file:
            findings.append(Finding.model_validate(json.load(file)))
    return findings
