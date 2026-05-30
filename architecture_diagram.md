# BreachLens Architecture Diagram

```mermaid
flowchart LR
  Analyst["SOC analyst"] --> UI["BreachLens React console"]
  UI --> API["FastAPI investigation API"]
  API --> Agent["Evidence-gated SOC agent"]
  Agent --> Mode{"Runtime mode"}
  Mode --> MCP["Splunk MCP Server"]
  Mode --> REST["Splunk REST fallback"]
  Mode --> Sample["Local sample-data client"]
  MCP --> Splunk["Local Splunk Enterprise"]
  REST --> Splunk
  Sample --> Data
  Splunk --> App["breachlens_splunk app"]
  App --> Data["Synthetic breach logs"]
  Agent --> LLM["Ollama NiNa or OpenAI-compatible model"]
  Agent --> Gate["Evidence reference gate"]
  Gate --> API
  API --> UI

  Splunk --> Searches["Saved searches and macros"]
  Searches --> UI
  UI --> Exports["Evidence ledger, report, detection drafts"]
```

## Data Flow

1. Synthetic authentication, EDR, cloud, proxy, and alert events are indexed into the `breachlens` Splunk index.
2. The analyst selects an alert in the React console and starts an investigation.
3. The FastAPI backend asks the SOC agent to create an investigation plan.
4. The agent uses Splunk MCP tools such as `splunk_run_query`, `splunk_get_indexes`, `splunk_get_metadata`, and `splunk_get_knowledge_objects`.
5. Ollama/NiNa or another OpenAI-compatible model can generate the analyst note, but output is accepted only when claims reference evidence IDs returned from Splunk queries.
6. The UI renders the incident timeline, MITRE ATT&CK mapping, evidence, SPL transcript, and detection drafts.

## Live Demo Proof Signals

- Runtime mode must show `mcp`.
- Splunk client must show `splunk_mcp`.
- AI runtime should show NiNa/Ollama and link to the Hugging Face model.
- MCP proof should show all four required tool calls: `splunk_get_indexes`, `splunk_get_metadata`, `splunk_get_knowledge_objects`, and `splunk_run_query`.
- Evidence cards should include source-event Splunk links when running against live Splunk.
