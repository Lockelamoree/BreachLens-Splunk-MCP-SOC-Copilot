from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.agent import run_investigation
from app.reports import build_evidence_ledger, build_incident_report_markdown
from app.splunk_client import SampleDataClient


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.investigation = run_investigation(
            SampleDataClient(REPO_ROOT / "sample_data"),
            "BLS-2026-001",
        )

    def test_evidence_ledger_links_claims_to_known_evidence(self) -> None:
        ledger = build_evidence_ledger(self.investigation)
        known = {item["id"] for item in ledger["evidence"]}
        self.assertGreater(ledger["claim_count"], 10)
        self.assertEqual(ledger["evidence_count"], len(self.investigation.evidence))
        for claim in ledger["claims"]:
            self.assertTrue(set(claim["evidence_ids"]).issubset(known))
            self.assertTrue(claim["spl_query_ids"])

    def test_incident_report_contains_summary_and_transcript(self) -> None:
        report = build_incident_report_markdown(self.investigation)
        self.assertIn("# BreachLens Incident Report", report)
        self.assertIn("## Evidence Ledger", report)
        self.assertIn("## AI Analyst Note", report)
        self.assertIn("```spl", report)
        self.assertIn("Estimated triage compression", report)


if __name__ == "__main__":
    unittest.main()
