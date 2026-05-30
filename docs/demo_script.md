# Demo Script Under 3 Minutes

## 0:00 - 0:20 Problem

"Security teams waste time jumping between alerts, SPL searches, and screenshots. BreachLens turns a suspicious alert into an evidence-backed investigation package using Splunk MCP Server."

## 0:20 - 0:45 Alert Queue

Show the React console and select `BLS-2026-001`. Call out the chain: password spraying, impossible travel, cloud token abuse, endpoint execution, and exfil-like traffic.

## 0:45 - 1:35 MCP Investigation

Click investigate. Show the SPL transcript proving the agent used Splunk-backed pivots. Mention that MCP tools provide the controlled interface: run queries, inspect indexes, metadata, and knowledge objects.

## 1:35 - 2:15 Evidence-Gated Findings

Walk the timeline. Each phase has evidence IDs, so the AI cannot invent a shell, credential, or impact claim. The likely path is account takeover to cloud abuse to endpoint execution to outbound data movement.

## 2:15 - 2:45 Detections, Ledger, and Response

Generate detections. Show SPL and Sigma-style output. Open an evidence chip to show raw Splunk fields, then export the Evidence Ledger or incident report. Call out immediate response: disable user, revoke sessions, rotate cloud keys, isolate host, block source IP, and preserve evidence.

## 2:45 - 3:00 Close

"This is not a chatbot pasted onto logs. It is a Splunk-native investigation workflow that produces reproducible evidence, response guidance, and reusable detections."
