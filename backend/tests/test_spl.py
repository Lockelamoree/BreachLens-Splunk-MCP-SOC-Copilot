from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.spl import build_investigation_queries, spl_string


class SplTests(unittest.TestCase):
    def test_spl_string_escapes_quotes(self) -> None:
        self.assertEqual(spl_string('a"b'), '"a\\"b"')

    def test_build_investigation_queries_has_required_pivots(self) -> None:
        queries = build_investigation_queries(
            {
                "alert_id": "BLS-2026-001",
                "user": "maria.chen",
                "src_ip": "203.0.113.45",
                "host": "LAPTOP-MCHEN",
            },
            "breachlens",
        )
        ids = {query.id for query in queries}
        self.assertEqual(ids, {"Q-alert", "Q-identity", "Q-cloud", "Q-endpoint", "Q-proxy"})
        self.assertTrue(all("index=breachlens" in query.spl for query in queries))


if __name__ == "__main__":
    unittest.main()

