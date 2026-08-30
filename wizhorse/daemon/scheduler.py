from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
from pathlib import Path
from typing import Mapping

from wizhorse import config

LOCK_PATTERNS = ("*.lock", "*.lock~", "*.ghidra")


class GhidraScheduler:
    """Serialize Ghidra headless operations and clean stale project locks.

    Ghidra lock files do not reliably expose the owning PID on Windows. The
    cleanup therefore first kills Java processes whose command line references
    the specific project directory or case hash, then removes remaining lock
    files as stale/orphaned for that project only.
    """

    def __init__(self) -> None:
        self._capacity = config.ghidra_max_concurrent_operations()
        self._semaphore = threading.BoundedSemaphore(self._capacity)

    def run_headless(
        self,
        *,
        case_id: str,
        operation: str,
        project_dir: Path,
        command: list[str],
        env: Mapping[str, str] | None = None,
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[str]:
        with self._semaphore:
            self.cleanup_project_locks(project_dir, case_id)
            process = subprocess.Popen(
                command,
                env=dict(env) if env is not None else None,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                self._terminate_process_tree(process.pid)
                stdout, stderr = process.communicate()
                self._remove_lock_files(project_dir)
                output = (stderr or stdout or "").strip()
                raise TimeoutError(
                    f"Ghidra {operation} timed out for case_id {case_id} "
                    f"after {timeout_seconds}s: {output[-2000:]}"
                ) from exc

            if process.returncode != 0:
                output = (stderr or stdout or "").strip()
                raise RuntimeError(
                    f"Ghidra {operation} failed for case_id {case_id} with exit code "
                    f"{process.returncode}: {output[-2000:]}"
                )

            return subprocess.CompletedProcess(
                command,
                process.returncode,
                stdout,
                stderr,
            )

    def cleanup_project_locks(self, project_dir: Path, case_id: str) -> None:
        lock_files = self._lock_files(project_dir)
        if not lock_files:
            return

        project_token = str(project_dir.resolve()).lower()
        case_token = case_id.lower()
        for process in _java_processes():
            command_line = process.command_line.lower()
            if project_token in command_line or case_token in command_line:
                self._terminate_process_tree(process.pid)

        self._remove_lock_files(project_dir)

    def _lock_files(self, project_dir: Path) -> list[Path]:
        if not project_dir.exists():
            return []
        lock_files: list[Path] = []
        for pattern in LOCK_PATTERNS:
            lock_files.extend(project_dir.rglob(pattern))
        return sorted({path.resolve() for path in lock_files})

    def _remove_lock_files(self, project_dir: Path) -> None:
        for lock_file in self._lock_files(project_dir):
            try:
                lock_file.unlink()
            except FileNotFoundError:
                continue
            except OSError:
                continue

    def _terminate_process_tree(self, pid: int) -> None:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass

            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            return

        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return


class JavaProcess:
    def __init__(self, pid: int, command_line: str) -> None:
        self.pid = pid
        self.command_line = command_line


def _java_processes() -> list[JavaProcess]:
    if os.name == "nt":
        return _windows_java_processes()
    return _posix_java_processes()


def _windows_java_processes() -> list[JavaProcess]:
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "Get-CimInstance Win32_Process "
            "-Filter \"name='java.exe' or name='javaw.exe'\" | "
            "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
        ),
    ]
    try:
        completed = subprocess.run(
            command,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0 or not completed.stdout.strip():
        return []

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return []

    processes: list[JavaProcess] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        pid = item.get("ProcessId")
        command_line = item.get("CommandLine") or ""
        if isinstance(pid, int):
            processes.append(JavaProcess(pid=pid, command_line=str(command_line)))
    return processes


def _posix_java_processes() -> list[JavaProcess]:
    try:
        completed = subprocess.run(
            ["ps", "-eo", "pid=,args="],
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []

    processes: list[JavaProcess] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped or "java" not in stripped.lower():
            continue
        pid_text, _, command_line = stripped.partition(" ")
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        processes.append(JavaProcess(pid=pid, command_line=command_line))
    return processes


scheduler = GhidraScheduler()
