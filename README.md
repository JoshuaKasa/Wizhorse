# Wizhorse 🐴

Wizhorse is your friendly wizard-horse assistant for making sense of Windows
file warnings. It checks a file without running it and helps explain whether a
warning may be a false positive, what evidence was found, and what remains
uncertain.

> Wizhorse never executes submitted files, but it copies them into local case
> storage for inspection. Its results are clues, not a guarantee that a file
> is safe.

It supports a lightweight local workflow for people who want a second opinion
on a suspicious download or a Windows detection:

- create a local case from a file path
- run safe, non-executing checks
- compare the file with available YARA and capa rules
- record the evidence and generate a Markdown report
- use Ghidra to inspect the file's functions, strings, and code paths

## Requirements

Wizhorse has one complete workflow; it is not offered in a reduced mode. Before
using it, install and configure all of the following:

- Python 3.10+
- Windows
- Ghidra
- a Java JDK compatible with your Ghidra installation
- Mandiant capa, available as `capa` on `PATH` or as `python -m capa.main`
- the `GHIDRA_INSTALL_DIR` and `JAVA_HOME` environment variables

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

## Workflow

After completing the required setup, Wizhorse uses these checks together:

- `create_case` and `run_static_triage` identify the file and its basic traits
- `run_yara`, `run_capa`, and `get_capa_locations` look for known signals
- Ghidra imports the file, analyzes it, and supplies functions, strings,
  cross-references, and decompiled code when the evidence needs explanation
- `record_finding` and `generate_report` preserve a clear, evidence-based
  conclusion

## Required External Tools

Ghidra and capa are required for the supported Wizhorse workflow. They are not
installed by `pip install -e .`, so configure them before connecting the MCP
server.

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

## Install Wizhorse as a Codex Skill

The repository includes a Codex skill that tells Codex how to set up and use
the complete Wizhorse workflow. Ask Codex to:

```text
Install the skill from GitHub repo JoshuaKasa/Wizhorse at skills/wizhorse.
```

Codex then reads `skills/wizhorse/SKILL.md`. The skill includes the required
setup, static-only safety rules, evidence standard, and user-friendly reporting
guidance.

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

## Third-party content

The bundled `capa-rules/` directory is the Mandiant capa rules collection and
is distributed under the Apache License 2.0; its license is retained at
[`capa-rules/LICENSE.txt`](capa-rules/LICENSE.txt). See the upstream project at
<https://github.com/mandiant/capa-rules> for rule updates and provenance.

## License

Wizhorse is released under the [MIT License](LICENSE). The bundled capa rules
remain available under their own Apache License 2.0 terms.

## Development

Run the test suite before contributing changes:

```powershell
python -m pytest -q
```

GitHub Actions runs these tests automatically for supported Python versions.
