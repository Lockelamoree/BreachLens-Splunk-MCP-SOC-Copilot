# BreachLens Live Validation

Date: `2026-05-30`

This is the honest state of the local validation environment.

## Current Live Splunk Path

The local Splunk Enterprise container is running with the BreachLens app installed:

```text
container: breachlens-splunk
app: breachlens_splunk
backend client: splunk_rest
runtime mode: rest
```

The local `breachlens` index currently has live indexed demo data:

```text
breachlens:alert  3
breachlens:auth   11
breachlens:cloud  5
breachlens:edr    3
breachlens:proxy  3
```

This validates the normal local live-data path: `rest / splunk_rest`.

## MCP Proof Status

MCP proof is still pending. I checked the local Splunk app directory and the Splunk MCP Server app is not installed yet:

```text
/opt/splunk/etc/apps
no *mcp* app found
```

That means I should not claim `mcp / splunk_mcp` proof yet. REST mode can show abstract tool names like `splunk_get_indexes`, but BreachLens now records `transport` on every transcript entry, and the UI only counts required tool calls as MCP proof when the transcript transport is actually `mcp`.

I also checked the official Splunkbase download URL for the MCP Server app. It redirects to a login-protected download and returns `401 Unauthorized` without an authenticated Splunkbase session. The next step is to download the `.tgz` manually from a logged-in Splunkbase session and place it in `.quarantine/` for triage and install.

## Command To Validate Final MCP Mode

After installing and configuring Splunk MCP Server locally:

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
