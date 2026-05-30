from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.agent import get_alerts, run_investigation
from app.splunk_client import SampleDataClient


class AgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = SampleDataClient(REPO_ROOT / "sample_data")

    def test_lists_alerts_by_severity(self) -> None:
        alerts = get_alerts(self.client)
        self.assertGreaterEqual(len(alerts), 3)
        self.assertEqual(alerts[0].alert_id, "BLS-2026-001")
        self.assertEqual(alerts[0].severity, "critical")

    def test_investigation_builds_evidence_gated_chain(self) -> None:
        investigation = run_investigation(self.client, "BLS-2026-001")
        self.assertEqual(investigation.status, "complete")
        self.assertEqual(investigation.confidence, "high")
        self.assertGreaterEqual(len(investigation.evidence), 10)
        phases = {event.phase for event in investigation.timeline}
        self.assertIn("Initial access", phases)
        self.assertIn("Cloud control plane", phases)
        self.assertIn("Exfiltration", phases)
        techniques = {mapping.technique_id for mapping in investigation.mitre}
        self.assertIn("T1110.003", techniques)
        self.assertIn("T1567.002", techniques)
        self.assertIsNotNone(investigation.analyst_note)
        self.assertEqual(investigation.analyst_note.provider, "deterministic")
        self.assertTrue(investigation.analyst_note.evidence_ids)
        known = {item.id for item in investigation.evidence}
        for event in investigation.timeline:
            self.assertTrue(set(event.evidence_ids).issubset(known))

    def test_context_tools_are_recorded(self) -> None:
        investigation = run_investigation(self.client, "BLS-2026-001")
        tools = {entry.tool for entry in investigation.spl_transcript}
        self.assertIn("splunk_get_indexes", tools)
        self.assertIn("splunk_get_metadata", tools)
        self.assertIn("splunk_get_knowledge_objects", tools)
        self.assertIn("splunk_run_query", tools)


if __name__ == "__main__":
    unittest.main()
