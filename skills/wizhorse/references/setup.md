# Wizhorse Setup

Install the complete toolchain before connecting the MCP server:

1. Install Python 3.10 or later on Windows.
2. Install Ghidra and a Java JDK supported by that Ghidra release.
3. Install Mandiant capa so either `capa` is on `PATH` or `python -m capa.main`
   works.
4. Clone the repository and install its Python dependencies with
   `python -m pip install -e .`.
5. Set `GHIDRA_INSTALL_DIR` to the Ghidra installation directory and
   `JAVA_HOME` to the JDK directory.
6. Start the MCP server with `python -m wizhorse.mcp.server`, or configure the
   supplied `.mcp.json` in the MCP client.

For example, in PowerShell:

```powershell
$env:GHIDRA_INSTALL_DIR="C:\Tools\ghidra_11.4_PUBLIC"
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-21"
python -m pip install -e .
python -m wizhorse.mcp.server
```

Keep submitted files in a dedicated workspace. Wizhorse copies them into local
case storage for static analysis, but it must never execute them.
