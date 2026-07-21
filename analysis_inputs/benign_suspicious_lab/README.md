## benign_suspicious_lab

This project contains a deliberately suspicious-looking but benign Windows test binary for
exercising Wizhorse static analysis.

Ground truth:

- The program is benign.
- It performs no network communication.
- It does not inject into, suspend, or modify any other process.
- It writes a demo autostart registry value and removes it immediately.
- It creates short-lived local artifacts and deletes them before exit.
- Its RWX memory region contains only a single `ret` instruction.

Intended use:

- Static triage calibration
- capa/YARA/Ghidra workflow testing
- False-positive and "heuristic-only" verdict validation

Build:

```powershell
pwsh -File .\build.ps1
```

Output:

- `bin\benign_suspicious_plus.exe`
