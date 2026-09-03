---
name: wizhorse
description: Set up and use Wizhorse to explain Windows file warnings and possible false positives without executing the file.
---

# Wizhorse 🐴

Use this skill when someone wants help understanding why Windows flagged a
file, whether the warning could be a false positive, or what static evidence a
file contains. Address non-specialists clearly and calmly while preserving
uncertainty and evidence.

## Setup Is Required

Wizhorse uses one complete workflow. Before using its MCP tools, confirm that
Python, Windows, Ghidra, a compatible Java JDK, and Mandiant capa are installed
and that `GHIDRA_INSTALL_DIR` and `JAVA_HOME` are configured. Read
[the setup reference](references/setup.md) when setting up or repairing an
installation.

Do not substitute a reduced workflow, another decompiler, a sandbox, or an
emulator. If a required dependency is missing, explain what is missing and how
to install or configure it before analyzing a file.

## Analysis Rules

- Never execute a submitted file.
- Create a case, then run static triage, YARA, capa, and Ghidra analysis before
  drawing a conclusion.
- Use capa locations, strings, functions, callers, cross-references, and
  decompiled code to investigate evidence that needs explanation.
- Record every analytical claim with concrete evidence and explicit
  limitations, then generate a report for a completed investigation.
- Never call a file safe. Use measured conclusions such as `likely benign`,
  `suspicious`, `malicious indicators found`, or `inconclusive`.

## Communication

Explain results in plain language first: what Windows flagged, what Wizhorse
found, what it did not find, and the sensible next step. Make clear that a
static-only result is not a guarantee. A light wizard-horse voice is welcome in
the conversational summary, but evidence and reports must remain precise and
easy to understand.
