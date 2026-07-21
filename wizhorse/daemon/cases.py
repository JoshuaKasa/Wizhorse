from __future__ import annotations

import hashlib
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from wizhorse.schemas.cases import Case

STORAGE_DIR = Path("storage")
DB_PATH = STORAGE_DIR / "wizhorse.db"
SAMPLES_DIR = STORAGE_DIR / "samples"
DEFAULT_STATUS = "created"
DEFAULT_ANALYSIS_PROFILE = "static"


def create_case(source_path: str) -> Case:
    source = Path(source_path).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"source file does not exist: {source_path}")

    sample_sha256 = _sha256_file(source)
    sample_dir = SAMPLES_DIR / sample_sha256
    sample_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, sample_dir / "sample.bin")

    case = Case(
        case_id=uuid.uuid4().hex,
        sample_sha256=sample_sha256,
        original_name=source.name,
        status=DEFAULT_STATUS,
        created_at=datetime.now(timezone.utc),
        analysis_profile=DEFAULT_ANALYSIS_PROFILE,
    )
    _insert_case(case)
    return case


def get_case(case_id: str) -> Case:
    _init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT case_id, sample_sha256, original_name, status, created_at, analysis_profile
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

    if row is None:
        raise KeyError(f"unknown case_id: {case_id}")
    return _case_from_row(row)


def list_cases() -> list[Case]:
    _init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT case_id, sample_sha256, original_name, status, created_at, analysis_profile
            FROM cases
            ORDER BY created_at DESC
            """
        ).fetchall()
    return [_case_from_row(row) for row in rows]


def update_case_status(case_id: str, status: str) -> None:
    _init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE cases SET status = ? WHERE case_id = ?",
            (status, case_id),
        )
    if cursor.rowcount == 0:
        raise KeyError(f"unknown case_id: {case_id}")


def get_sample_path(case: Case) -> Path:
    return SAMPLES_DIR / case.sample_sha256 / "sample.bin"


def _insert_case(case: Case) -> None:
    _init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO cases (
                case_id, sample_sha256, original_name, status, created_at, analysis_profile
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                case.case_id,
                case.sample_sha256,
                case.original_name,
                case.status,
                case.created_at.isoformat(),
                case.analysis_profile,
            ),
        )


def _init_db() -> None:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                sample_sha256 TEXT NOT NULL,
                original_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                analysis_profile TEXT NOT NULL
            )
            """
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _case_from_row(row: sqlite3.Row) -> Case:
    return Case(
        case_id=row["case_id"],
        sample_sha256=row["sample_sha256"],
        original_name=row["original_name"],
        status=row["status"],
        created_at=datetime.fromisoformat(row["created_at"]),
        analysis_profile=row["analysis_profile"],
    )
