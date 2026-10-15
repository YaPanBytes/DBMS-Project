"""Tests for the AI services that don't need a database (plus one that does)."""

from datetime import UTC, datetime
from uuid import uuid4

import numpy as np
import pandas as pd
import pytest

from ai import anomaly
from ai.log_generator import BULK_EXPORT, NORMAL, OFF_HOURS, Actor, generate_access_log
from ai.pii import infer_type, scan_column, scan_rows


def actors(n: int = 6) -> list[Actor]:
    return [
        Actor(uuid4(), uuid4(), tuple(uuid4() for _ in range(4)), typical_rows=100)
        for _ in range(n)
    ]


class TestGenerator:
    def test_deterministic_with_labels(self):
        a = actors()
        now = datetime(2026, 10, 15, 12, tzinfo=UTC)
        e1 = generate_access_log(a, now=now, seed=1)
        e2 = generate_access_log(a, now=now, seed=1)
        assert [(e.ts, e.rows) for e in e1] == [(e.ts, e.rows) for e in e2]
        labels = {e.label for e in e1}
        assert {NORMAL, BULK_EXPORT, OFF_HOURS} <= labels
        assert all(e.ts < now for e in e1)

    def test_patterns_have_their_shape(self):
        events = generate_access_log(actors(), now=datetime(2026, 10, 15, 12, tzinfo=UTC), seed=3)
        bulk = [e for e in events if e.label == BULK_EXPORT]
        off = [e for e in events if e.label == OFF_HOURS]
        normal = [e for e in events if e.label == NORMAL]
        assert min(e.rows for e in bulk) >= 4000
        assert all(1 <= e.ts.hour <= 5 for e in off)
        assert all(9 <= e.ts.hour <= 21 for e in normal)


class TestPII:
    def test_detects_identifiers(self):
        rows = [
            {
                "email": f"user{i}@example.org",
                "mobile": f"+91 98765 4{i:04d}",
                "aadhaar": f"2345 6789 {1000 + i}",
                "village": "Wardha",
                "members": str(i % 7),
            }
            for i in range(30)
        ]
        report = {f.name: f for f in scan_rows(rows, use_ner=False).fields}
        assert report["email"].suggested_sensitivity == "pii"
        assert report["mobile"].suggested_sensitivity == "pii"
        assert report["aadhaar"].suggested_sensitivity == "pii"
        assert report["village"].suggested_sensitivity == "low"
        assert report["members"].inferred_type == "integer"
        assert all("@" not in str(v) for v in report["email"].masked_preview)

    def test_card_numbers_need_luhn(self):
        assert scan_column("card", ["4111 1111 1111 1111"] * 5, use_ner=False).detected == {
            "credit_card": 1.0
        }
        assert (
            "credit_card"
            not in scan_column("ref", ["4111 1111 1111 1112"] * 5, use_ner=False).detected
        )

    def test_name_hints_and_types(self):
        assert scan_column("income", ["100", "200"], use_ner=False).suggested_sensitivity == "high"
        assert infer_type(["2026-01-02", "2025-12-31"]) == "date"
        assert infer_type(["yes", "no"]) == "boolean"

    def test_ner_finds_names_in_free_text(self):
        from ai.pii import ner_available

        if not ner_available():
            pytest.skip("spaCy model not installed")
        r = scan_column(
            "notes", ["Met Priya Sharma in Pune", "Called Rahul Verma about rations"] * 5
        )
        assert "person_name" in r.detected and r.suggested_sensitivity == "pii"


class TestAnomaly:
    def _frame(self) -> pd.DataFrame:
        rng = np.random.default_rng(0)
        n = 300
        df = pd.DataFrame(
            {
                "user_id": [f"u{i % 20}" for i in range(n)],
                "hour_bucket": pd.date_range("2026-09-01", periods=n, freq="h"),
                "query_count": rng.poisson(3, n) + 1,
                "distinct_datasets": 1,
                "distinct_fields": rng.integers(1, 5, n),
                "total_rows_read": rng.integers(50, 400, n),
                "max_rows_per_query": rng.integers(20, 200, n),
                "off_hours_count": 0,
                "off_hours_share": 0.0,
                "rows_per_request": rng.uniform(30, 150, n),
                "rows_vs_baseline": rng.uniform(0.7, 1.4, n),
                "baseline_rows_read": 200.0,
            }
        )
        df["select_count"] = df["query_count"]
        # two injected anomalies
        df.loc[
            10,
            [
                "query_count",
                "select_count",
                "total_rows_read",
                "max_rows_per_query",
                "rows_vs_baseline",
            ],
        ] = [28, 28, 220000, 11000, 900]
        df.loc[20, ["off_hours_count", "off_hours_share", "query_count", "select_count"]] = [
            8,
            1.0,
            8,
            8,
        ]
        return df

    def test_isolation_forest_flags_injected(self):
        res = anomaly.score(self._frame(), contamination=0.02)
        flagged = set(res.frame.index[res.frame["if_flag"]])
        assert {10, 20} <= flagged
        assert res.frame.loc[10, "if_score"] > 0.9

    def test_rule_baseline_and_evaluation(self):
        res = anomaly.score(self._frame(), contamination=0.02)
        f = res.frame
        truth = {(f.loc[i, "user_id"], f.loc[i, "hour_bucket"]) for i in (10, 20)}
        ev = anomaly.evaluate(f, truth)
        assert ev["anomalous_user_hours"] == 2 and ev["isolation_forest"]["recall"] == 1.0
        assert ev["rule_baseline"]["tp"] == 2

    def test_reason_is_readable(self):
        f = anomaly.score(self._frame(), contamination=0.02).frame
        reason = anomaly.explain(f.loc[10], f[f["user_id"] == f.loc[10, "user_id"]])
        assert "rows in one hour" in reason and reason[0].isupper()

    def test_detector_on_seeded_db(self, seeded, migrated_engine):
        summary = anomaly.detect_and_store(migrated_engine, labels_path=None, save_model=False)
        assert summary["user_hours"] > 100
        again = anomaly.detect_and_store(migrated_engine, labels_path=None, save_model=False)
        assert again["alerts_written"] == 0  # idempotent
