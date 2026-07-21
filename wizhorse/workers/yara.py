from __future__ import annotations

from pathlib import Path
from typing import Any

from wizhorse import config
from wizhorse.daemon.cases import SAMPLES_DIR, get_sample_path
from wizhorse.schemas.cases import Case
from wizhorse.schemas.yara import YaraMatch, YaraResult, YaraStringMatch


def run_yara(case: Case) -> YaraResult:
    try:
        import yara
    except ImportError:
        return _persist(
            case,
            YaraResult(
                case_id=case.case_id,
                sample_sha256=case.sample_sha256,
                rule_dir=str(config.yara_rules_dir()),
                matched=False,
                matches=[],
                warnings=["yara-python not found, install the yara-python package"],
                error="yara-python not found, install the yara-python package",
            ),
        )

    rule_dir = config.yara_rules_dir()
    rule_paths = _rule_paths(rule_dir)
    if not rule_paths:
        return _persist(
            case,
            YaraResult(
                case_id=case.case_id,
                sample_sha256=case.sample_sha256,
                rule_dir=str(rule_dir),
                matched=False,
                matches=[],
                warnings=[f"no .yar or .yara files found in {rule_dir}"],
                error=None,
            ),
        )

    try:
        rules = yara.compile(
            filepaths={_namespace_for(path): str(path) for path in rule_paths}
        )
        raw_matches = rules.match(str(get_sample_path(case)))
    except yara.Error as exc:
        return _persist(
            case,
            YaraResult(
                case_id=case.case_id,
                sample_sha256=case.sample_sha256,
                rule_dir=str(rule_dir),
                matched=False,
                matches=[],
                warnings=[f"YARA failed: {exc}"],
                error=f"YARA failed: {exc}",
            ),
        )

    matches = [_match_from_yara(match) for match in raw_matches]
    return _persist(
        case,
        YaraResult(
            case_id=case.case_id,
            sample_sha256=case.sample_sha256,
            rule_dir=str(rule_dir),
            matched=bool(matches),
            matches=matches,
            warnings=[] if matches else ["YARA completed with no rule matches"],
            error=None,
        ),
    )


def _rule_paths(rule_dir: Path) -> list[Path]:
    if not rule_dir.exists():
        return []
    return sorted(
        path
        for path in rule_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yar", ".yara"}
    )


def _namespace_for(path: Path) -> str:
    return path.stem.replace("-", "_").replace(".", "_")


def _match_from_yara(match: Any) -> YaraMatch:
    return YaraMatch(
        rule=str(match.rule),
        namespace=str(match.namespace) if match.namespace else None,
        tags=[str(tag) for tag in match.tags],
        strings=_string_matches(match),
    )


def _string_matches(match: Any) -> list[YaraStringMatch]:
    strings: list[YaraStringMatch] = []
    for string_match in getattr(match, "strings", []):
        identifier = str(getattr(string_match, "identifier", ""))
        instances = getattr(string_match, "instances", None)
        if instances is not None:
            for instance in instances:
                strings.append(
                    YaraStringMatch(
                        identifier=identifier,
                        offset=int(getattr(instance, "offset", 0)),
                        data=_hex_data(getattr(instance, "matched_data", None)),
                    )
                )
            continue

        if isinstance(string_match, tuple) and len(string_match) >= 3:
            offset, legacy_identifier, data = string_match[:3]
            strings.append(
                YaraStringMatch(
                    identifier=str(legacy_identifier),
                    offset=int(offset),
                    data=_hex_data(data),
                )
            )
    return strings


def _hex_data(data: Any) -> str | None:
    if data is None:
        return None
    if isinstance(data, bytes):
        return data[:64].hex()
    return str(data)[:128]


def _persist(case: Case, result: YaraResult) -> YaraResult:
    path = _result_path(case)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return result


def _result_path(case: Case) -> Path:
    return SAMPLES_DIR / case.sample_sha256 / "yara.json"
