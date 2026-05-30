from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.agent import run_investigation
from app.detections import generate_detection_drafts
from app.splunk_client import SampleDataClient


class DetectionTests(unittest.TestCase):
    def test_detections_reference_known_evidence(self) -> None:
        investigation = run_investigation(SampleDataClient(REPO_ROOT / "sample_data"), "BLS-2026-001")
        drafts = generate_detection_drafts(investigation)
        self.assertEqual(len(drafts), 3)
        known = {item.id for item in investigation.evidence}
        for draft in drafts:
            self.assertTrue(draft.spl.startswith("`breachlens_index`"))
            self.assertIn("title:", draft.sigma)
            self.assertTrue(set(draft.evidence_ids).issubset(known))
            self.assertTrue(draft.evidence_ids)


if __name__ == "__main__":
    unittest.main()

