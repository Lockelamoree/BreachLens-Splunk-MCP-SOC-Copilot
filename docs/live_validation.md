# BreachLens Live Validation

Date: `2026-05-30`

This is the honest state of the local validation environment.

## Current Live Splunk Path

The local Splunk Enterprise container is running with the BreachLens app and Splunk MCP Server installed:

```text
container: breachlens-splunk
app: breachlens_splunk
app: Splunk_MCP_Server 1.2.0
backend client: splunk_mcp
runtime mode: mcp
```

The local `breachlens` index currently has live indexed demo data:

```text
breachlens:alert  3
breachlens:auth   11
breachlens:cloud  5
breachlens:edr    3
breachlens:proxy  3
```

This validates that the demo data is indexed in local Splunk. The final demo path now runs through `mcp / splunk_mcp`.

## MCP Proof Status

MCP proof is now validated against the local Splunk instance. The generated proof file is [mcp_validation.md](mcp_validation.md).

```text
runtime: mcp / splunk_mcp
endpoint: https://localhost:18089/services/mcp
required tools observed: true
evidence items: 23
```

REST mode can still show abstract tool names like `splunk_get_indexes`, so I keep the transport check explicit. BreachLens records `transport` on every transcript entry, and the UI only counts the four required tool calls as MCP proof when the backend is actually running `mcp / splunk_mcp`.

The installed Splunk MCP Server package was downloaded manually from Splunkbase, placed under `.quarantine/`, hash-checked, statically triaged, and then installed into the local Splunk container.

## Command To Validate Final MCP Mode

After installing and configuring Splunk MCP Server locally:

```powershell
.\backend\.venv\Scripts\python.exe backend\scripts\validate_mcp.py --out docs\mcp_validation.md
```

```powershell
cd frontend
$env:EXPECTED_BREACHLENS_MODE = "mcp"
$env:EXPECTED_SPLUNK_CLIENT = "splunk_mcp"
$env:EXPECTED_AI_MODEL_LABEL = "NiNa"
npm run test:live
```

The final recording should show:

```text
Splunk MCP live
mcp
splunk_mcp
NiNa
4/4 observed
transport=mcp in the SPL transcript
```
