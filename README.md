# Wizhorse

Wizhorse is an evidence-driven static malware triage assistant exposed as an MCP server.

It supports a lightweight local workflow:

- create a case from a sample path
- run static triage
- run YARA and capa when available
- import the sample into Ghidra for static reverse engineering
- record findings with evidence
- generate a Markdown report

## Requirements

- Python 3.10+
- Windows is the primary supported environment for the Ghidra workflow

## Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
```

This installs the Python package and its base dependencies, including:

- `pydantic`
- `mcp`
- `Jinja2`
- `yara-python`
- `pefile`

`yara-python` and `pefile` are part of the base install, so no extra manual step is required for YARA-backed matching or PE-aware static triage.

## Feature Tiers

### Base Workflow

Available after a fresh clone and `pip install -e .`:

- `create_case`
- `run_static_triage`
- `record_finding`
- `run_yara`
- `generate_report`

### Advanced Workflow

Requires external `capa` setup in addition to the base install:

- `run_capa`
- `get_capa_locations`

### Reverse Workflow

Requires local Ghidra and Java setup in addition to the base install:

- `import_and_analyze`
- `list_functions`
- `decompile_function`
- `get_xrefs`

## Optional External Tools

Some features require tools that are not installed by `pip install -e .`.

### capa

`run_capa` requires Mandiant capa to be installed separately and available either:

- as `capa` on `PATH`
- or as a Python module importable as `python -m capa.main`

If capa signatures are not in the default location, set:

```powershell
$env:WIZHORSE_CAPA_SIGNATURES_PATH="C:\path\to\capa\sigs"
```

The bundled `capa-rules/` directory is used by default for rules. If you want a different rules directory:

```powershell
$env:WIZHORSE_CAPA_RULES_PATH="C:\path\to\capa-rules"
```

### Ghidra

The Ghidra-backed tools require:

- Ghidra installed locally
- Java installed locally
- `GHIDRA_INSTALL_DIR` set to the Ghidra install directory
- `JAVA_HOME` set to the JDK directory

Example:

```powershell
$env:GHIDRA_INSTALL_DIR="C:\Tools\ghidra_11.4_PUBLIC"
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-21"
```

These tools depend on that setup:

- `import_and_analyze`
- `list_functions`
- `decompile_function`
- `get_xrefs`

## MCP Setup

The repository includes a minimal `.mcp.json`:

```json
{
  "mcpServers": {
    "wizhorse": {
      "command": "python",
      "args": ["-m", "wizhorse.mcp.server"]
    }
  }
}
```

You can also run the server directly:

```powershell
python -m wizhorse.mcp.server
```

## Environment Variables

Supported configuration includes:

- `WIZHORSE_ALLOWED_ROOTS`
- `WIZHORSE_YARA_RULES_DIR`
- `WIZHORSE_CAPA_RULES_PATH`
- `WIZHORSE_CAPA_SIGNATURES_PATH`
- `WIZHORSE_CAPA_TIMEOUT_SECONDS`
- `GHIDRA_INSTALL_DIR`
- `JAVA_HOME`
- `WIZHORSE_GHIDRA_IMPORT_TIMEOUT_SECONDS`
- `WIZHORSE_GHIDRA_FAST_MANAGED_IMPORT_ENABLED`
- `WIZHORSE_GHIDRA_MANAGED_ANALYSIS_TIMEOUT_PER_FILE_SECONDS`
- `WIZHORSE_GHIDRA_DECOMPILE_TIMEOUT_SECONDS`
- `WIZHORSE_GHIDRA_QUERY_TIMEOUT_SECONDS`
- `WIZHORSE_GHIDRA_MAX_CONCURRENT_OPERATIONS`

## Notes

- The workflow is static-only. Samples should not be executed directly.
- Analysis state is stored under `storage/`.
- `analysis_inputs/` is intentionally ignored by Git and treated as local workspace material.
- The malware-analysis skill and generated report now use a restrained "wizard horse" voice for summaries, while keeping findings, evidence, and limitations technically explicit.
