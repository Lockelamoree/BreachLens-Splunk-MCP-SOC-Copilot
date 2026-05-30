# Demo Script Under 3 Minutes

This is the version I want to record. It keeps the story direct and leaves room to show the product instead of narrating every button like a training video from 2009.

## 0:00 - 0:20 Problem

"I built BreachLens because I wanted an AI-assisted SOC workflow that still behaves like security tooling. It should speed up triage, but every claim needs to trace back to Splunk evidence."

## 0:20 - 0:45 Proof Strip And Alert

Show the first screen. Call out the proof strip: runtime mode, Splunk client, NiNa/Ollama, MCP tool count, and evidence count.

Select `BLS-2026-001` and summarize the chain: password spraying, impossible travel, cloud token activity, endpoint execution, and outbound transfer.

## 0:45 - 1:35 Investigation

Click Investigate.

In MCP mode, show the proof strip updating to `4/4 observed`. Then open the SPL tab and show the tool names and `transport=mcp`:

- `splunk_get_indexes`
- `splunk_get_metadata`
- `splunk_get_knowledge_objects`
- `splunk_run_query`

Say: "The point is not just that the app found results. The point is that the tool path is visible, and REST is not being counted as MCP."

## 1:35 - 2:15 Evidence-Gated Findings

Walk the timeline. Click one or two evidence IDs.

Say: "The AI note is allowed to summarize, but it has to cite evidence IDs and concrete fields that came back from Splunk. If it does not, the backend falls back instead of trusting it."

Open the evidence drawer and show raw fields plus the Splunk source-event link.

## 2:15 - 2:45 Detections, Ledger, And Response

Generate detections. Show the SPL/Sigma-style draft.

Export the evidence ledger or report. Mention the response actions: disable the user, revoke sessions, rotate cloud keys, isolate the host, block the source IP, and preserve evidence.

## 2:45 - 3:00 Close

"This is not chat pasted onto logs. BreachLens is a Splunk-backed investigation workflow with AI kept inside an evidence gate."
