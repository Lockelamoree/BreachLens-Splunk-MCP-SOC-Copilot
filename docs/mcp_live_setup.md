# BreachLens MCP Live Setup

This is the path I need for the final Splunk MCP proof. REST mode proves live Splunk data; MCP mode proves the bonus target.

## 1. Download The MCP App

Download the official Splunk MCP Server app from Splunkbase:

```text
https://splunkbase.splunk.com/app/7931
```

Splunkbase requires login for the app archive. Put the downloaded `.tgz` here:

```text
.quarantine/splunk-mcp-server_120.tgz
```

Before install, verify the SHA256 shown by Splunkbase for the downloaded version. For the local version `1.2.0` package I downloaded, my local hash is:

```text
fa3c2d7ef500148d9ee2f2b92f1b2e5e3026401ca57138ffdfab20710f7d695c
```

## 2. Install Into Local Splunk

```powershell
$env:SPLUNK_PASSWORD = "<local admin password>"
.\scripts\install_splunk_mcp_app.ps1 -PackagePath .\.quarantine\splunk-mcp-server_120.tgz
```

Restart Splunk if the installer asks for it:

```powershell
docker restart breachlens-splunk
```

## 3. Configure MCP Access

Open Splunk Web:

```text
http://127.0.0.1:18000
```

Then:

1. Open the Splunk MCP Server app.
2. Grant `mcp_tool_execute` to the demo role/user.
3. Grant `mcp_tool_admin` and `edit_tokens_own` only to the user generating the encrypted token.
4. Generate an encrypted MCP token.
5. Copy the endpoint URL and token.

## 4. Switch BreachLens To MCP

Set these in `.env`:

```text
BREACHLENS_MODE=mcp
SPLUNK_MCP_URL=<endpoint shown by the Splunk MCP Server app>
SPLUNK_MCP_TOKEN=<encrypted MCP token>
SPLUNK_MCP_VERIFY_TLS=false
```

Keep `SPLUNK_MCP_VERIFY_TLS=false` only for this localhost/self-signed-cert demo. Production should use verified TLS.

## 5. Validate MCP Proof

```powershell
.\backend\.venv\Scripts\python.exe backend\scripts\validate_mcp.py --out docs\mcp_validation.md
```

Then run the UI proof:

```powershell
cd frontend
$env:EXPECTED_BREACHLENS_MODE = "mcp"
$env:EXPECTED_SPLUNK_CLIENT = "splunk_mcp"
$env:EXPECTED_AI_MODEL_LABEL = "NiNa"
npm run test:live
```

The proof I need for the video is:

```text
Splunk MCP live
mcp
splunk_mcp
4/4 observed
transport=mcp
```

BreachLens keeps the required logical labels visible in the transcript and proof strip. With Splunk MCP Server 1.2.0, the backend maps those labels to the installed server tool names, such as `get_indexes`, `get_metadata`, `get_knowledge_objects`, and `run_query`.
