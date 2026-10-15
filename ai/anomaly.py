"""
Access anomaly detection.

Input: per-user, per-hour features computed in SQL with window functions
(view ``access_features_hourly``: reads per hour, distinct fields touched,
rows per request, off-hours share, ratio to the user's rolling baseline, ...).

Models:
* Isolation Forest (scikit-learn), unsupervised, trained on the access history;
* a simple threshold rule as the baseline for comparison.

Output: rows in ``anomaly_alerts`` (score in [0, 1] and a short human-readable
reason) plus an ``anomaly_alert`` entry in the audit chain. Re-running is
idempotent: an alert is written once per (user, hour, detector).

    python -m ai.anomaly                 # score, write alerts, print evaluation
    python -m ai.anomaly --dry-run       # score and evaluate only
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy import Engine, text

FEATURES = [
    "query_count",
    "select_count",
    "distinct_datasets",
    "distinct_fields",
    "total_rows_read",
    "max_rows_per_query",
    "rows_per_request",
    "off_hours_share",
    "rows_vs_baseline",
]
LOG_FEATURES = {
    "query_count",
    "select_count",
    "distinct_fields",
    "total_rows_read",
    "max_rows_per_query",
    "rows_per_request",
    "rows_vs_baseline",
}

# Rule-based baseline thresholds
RULE_MAX_ROWS_PER_QUERY = 2000
RULE_TOTAL_ROWS_PER_HOUR = 20000
RULE_OFF_HOURS_READS = 3

MODEL_PATH = Path(__file__).resolve().parent / "models" / "isolation_forest.joblib"
DEFAULT_LABELS = Path(__file__).resolve().parent / "data" / "labels.csv"

FEATURE_SQL = """
SELECT f.*,
       u.org_id,
       (SELECT a.dataset_id
          FROM audit_log a
         WHERE a.user_id = f.user_id
           AND a.action = 'select'
           AND date_trunc('hour', a.ts AT TIME ZONE 'UTC') = f.hour_bucket
         GROUP BY a.dataset_id
         ORDER BY sum(a.rows_affected) DESC
         LIMIT 1) AS top_dataset_id
FROM access_features_hourly f
JOIN users u ON u.user_id = f.user_id
WHERE f.select_count > 0
ORDER BY f.user_id, f.hour_bucket
"""


@dataclass
class DetectionResult:
    frame: pd.DataFrame  # one row per user-hour with scores and flags
    model: IsolationForest


def load_features(engine: Engine) -> pd.DataFrame:
    with engine.connect() as conn:
        df = pd.read_sql(text(FEATURE_SQL), conn)
    return df


def _matrix(df: pd.DataFrame) -> np.ndarray:
    x = df[FEATURES].astype(float).copy()
    x["rows_vs_baseline"] = x["rows_vs_baseline"].fillna(1.0).clip(0, 1000)
    x["rows_per_request"] = x["rows_per_request"].fillna(0.0)
    x = x.fillna(0.0)
    for col in LOG_FEATURES:
        x[col] = np.log1p(x[col].clip(lower=0))
    return x.to_numpy()


def rule_flags(df: pd.DataFrame) -> pd.Series:
    return (
        (df["max_rows_per_query"] >= RULE_MAX_ROWS_PER_QUERY)
        | (df["total_rows_read"] >= RULE_TOTAL_ROWS_PER_HOUR)
        | (df["off_hours_count"] >= RULE_OFF_HOURS_READS)
    )


def score(df: pd.DataFrame, *, contamination: float = 0.01, seed: int = 42) -> DetectionResult:
    """Fit the Isolation Forest on the history and score every user-hour."""
    df = df.copy()
    x = _matrix(df)
    model = IsolationForest(n_estimators=300, contamination=contamination, random_state=seed)
    model.fit(x)
    raw = -model.score_samples(x)  # higher = more anomalous
    lo, hi = float(raw.min()), float(raw.max())
    df["if_score"] = (raw - lo) / (hi - lo) if hi > lo else 0.0
    df["if_flag"] = model.predict(x) == -1
    df["rule_flag"] = rule_flags(df)
    return DetectionResult(frame=df, model=model)


def explain(row: pd.Series, user_hist: pd.DataFrame) -> str:
    """Short reason built from the features that deviate most."""
    reasons: list[str] = []
    typical_rows = float(user_hist["total_rows_read"].median()) if len(user_hist) else 0.0
    typical_q = float(user_hist["query_count"].median()) if len(user_hist) else 0.0

    if row["off_hours_count"] >= 1 and row["off_hours_share"] >= 0.5:
        reasons.append(
            f"{int(row['off_hours_count'])} of {int(row['query_count'])} reads "
            "were off-hours (outside 08:00-19:00 UTC)"
        )
    if typical_rows > 0 and row["total_rows_read"] >= 5 * typical_rows:
        reasons.append(
            f"read {int(row['total_rows_read']):,} rows in one hour, "
            f"{row['total_rows_read'] / typical_rows:.0f}x this user's typical hour"
        )
    elif row["total_rows_read"] >= RULE_TOTAL_ROWS_PER_HOUR:
        reasons.append(f"read {int(row['total_rows_read']):,} rows in one hour")
    if row["max_rows_per_query"] >= RULE_MAX_ROWS_PER_QUERY:
        reasons.append(f"largest single read {int(row['max_rows_per_query']):,} rows")
    if typical_q > 0 and row["query_count"] >= 3 * typical_q and row["query_count"] >= 6:
        reasons.append(f"{int(row['query_count'])} reads in one hour (usually {typical_q:.0f})")
    if not reasons:
        reasons.append("unusual combination of volume, fields and timing for this user")
    text_ = "; ".join(reasons)
    return text_[0].upper() + text_[1:]


def _labelled_hours(engine: Engine, labels: dict[str, str]) -> set[tuple[str, pd.Timestamp]]:
    """User-hours that contain at least one injected anomalous event."""
    anomalous = [k for k, v in labels.items() if v != "normal"]
    if not anomalous:
        return set()
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT DISTINCT user_id::text, date_trunc('hour', ts AT TIME ZONE 'UTC') "
                "FROM audit_log WHERE log_id = ANY(CAST(:ids AS uuid[]))"
            ),
            {"ids": anomalous},
        ).all()
    return {(u, pd.Timestamp(h)) for u, h in rows}


def evaluate(frame: pd.DataFrame, positives: set[tuple[str, pd.Timestamp]]) -> dict[str, Any]:
    """Precision / recall / F1 of both detectors at user-hour level."""
    truth = np.array(
        [
            (str(u), pd.Timestamp(h)) in positives
            for u, h in zip(frame["user_id"], frame["hour_bucket"], strict=True)
        ]
    )
    out: dict[str, Any] = {"user_hours": len(frame), "anomalous_user_hours": int(truth.sum())}
    for name, col in (("isolation_forest", "if_flag"), ("rule_baseline", "rule_flag")):
        pred = frame[col].to_numpy()
        tp = int((pred & truth).sum())
        fp = int((pred & ~truth).sum())
        fn = int((~pred & truth).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        out[name] = {
            "flagged": int(pred.sum()),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        }
    return out


def _clean(value: Any) -> Any:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating, float)):
        return None if math.isnan(float(value)) else round(float(value), 4)
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    return value


def store_alerts(engine: Engine, frame: pd.DataFrame) -> int:
    """Write one alert per flagged (user, hour, detector); skip existing ones."""
    written = 0
    with engine.begin() as conn:
        existing = {
            (str(u), h, d)
            for u, h, d in conn.execute(
                text(
                    "SELECT user_id, features->>'hour_bucket', detector FROM anomaly_alerts "
                    "WHERE detector IN ('isolation_forest', 'rule')"
                )
            )
        }
        for _, row in frame[frame["if_flag"] | frame["rule_flag"]].iterrows():
            hist = frame[frame["user_id"] == row["user_id"]]
            reason = explain(row, hist)
            features = {
                k: _clean(row[k]) for k in FEATURES + ["off_hours_count", "baseline_rows_read"]
            }
            features["hour_bucket"] = pd.Timestamp(row["hour_bucket"]).isoformat()
            detector = "isolation_forest" if row["if_flag"] else "rule"
            if (str(row["user_id"]), features["hour_bucket"], detector) in existing:
                continue
            score_value = (
                float(row["if_score"])
                if detector == "isolation_forest"
                else max(float(row["if_score"]), 0.5)
            )
            features["also_flagged_by_rule"] = bool(row["rule_flag"])
            conn.execute(
                text(
                    "INSERT INTO anomaly_alerts (user_id, dataset_id, score, reason, features, detector) "
                    "VALUES (:u, :d, :s, :r, CAST(:f AS jsonb), :det)"
                ),
                {
                    "u": row["user_id"],
                    "d": row["top_dataset_id"],
                    "s": round(score_value, 4),
                    "r": reason,
                    "f": json.dumps(features),
                    "det": detector,
                },
            )
            conn.execute(
                text(
                    "SELECT append_audit_log(NULL, 'anomaly_alert', p_dataset_id => :d, "
                    "p_query_text => :q)"
                ),
                {
                    "d": row["top_dataset_id"],
                    "q": f"{detector} flagged user {row['user_id']} at {features['hour_bucket']}",
                },
            )
            written += 1
    return written


def detect_and_store(
    engine: Engine | None = None,
    *,
    contamination: float = 0.01,
    labels_path: str | Path | None = DEFAULT_LABELS,
    write: bool = True,
    save_model: bool = True,
) -> dict[str, Any]:
    from database.connection import get_engine

    engine = engine or get_engine()
    df = load_features(engine)
    if len(df) < 10:
        return {"user_hours": len(df), "alerts_written": 0, "note": "not enough history to train"}

    result = score(df, contamination=contamination)
    summary: dict[str, Any] = {
        "user_hours": len(df),
        "isolation_forest_flags": int(result.frame["if_flag"].sum()),
        "rule_flags": int(result.frame["rule_flag"].sum()),
    }
    if labels_path and Path(labels_path).exists():
        from ai.log_generator import load_labels

        summary["evaluation"] = evaluate(
            result.frame, _labelled_hours(engine, load_labels(labels_path))
        )
    if save_model:
        try:
            import joblib

            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump({"model": result.model, "features": FEATURES}, MODEL_PATH)
        except Exception:  # model persistence is optional
            pass
    summary["alerts_written"] = store_alerts(engine, result.frame) if write else 0
    return summary


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Detect anomalous access patterns")
    parser.add_argument("--contamination", type=float, default=0.01)
    parser.add_argument("--labels", default=str(DEFAULT_LABELS))
    parser.add_argument("--dry-run", action="store_true", help="do not write alerts")
    args = parser.parse_args()

    summary = detect_and_store(
        contamination=args.contamination, labels_path=args.labels, write=not args.dry_run
    )
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
