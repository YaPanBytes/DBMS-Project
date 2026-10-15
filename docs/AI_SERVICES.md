# AI Services

All code is in `ai/`. Each module has a command-line entry point.

## Synthetic access-log generator (`ai/log_generator.py`)

```bash
python -m ai.log_generator --days 30 --bulk 2 --off-hours 3 --slow 2 --labels-out ai/data/labels.csv
```

Builds "actors" from the database (partners reading what they were granted,
owners reading their own data) and generates:

- **normal** reads on weekdays, 09:00-17:59 UTC, Poisson-distributed per day,
  log-normal row counts around each actor's typical volume, a subset of fields;
- legitimate **evening reads** (19:00-21:59) as noise;
- **bulk_export**: 18-30 reads in one hour, 4,000-12,000 rows each, every field;
- **off_hours**: 6-10 reads between 01:00 and 04:59 UTC;
- **slow_exfiltration**: 10-14 reads of 900-1,500 rows in an hour, all fields,
  each below the rule thresholds.

Events are inserted into `audit_log` (the database trigger chains them) and the
labels are written to CSV for evaluation.

## Anomaly detector (`ai/anomaly.py`)

```bash
python -m ai.anomaly            # score, write alerts, print evaluation
python -m ai.anomaly --dry-run  # evaluate only
```

- **Input:** `access_features_hourly` (window-function features computed in SQL).
- **Model:** scikit-learn `IsolationForest` (300 trees, contamination 1%) on
  log-scaled counts, off-hours share and the ratio to each user's rolling baseline.
- **Baseline:** a threshold rule (any read ≥ 2,000 rows, ≥ 20,000 rows in an hour,
  or ≥ 3 off-hours reads).
- **Output:** one `anomaly_alerts` row per flagged user-hour and detector with a
  0-1 score and a readable reason ("Read 228,144 rows in one hour, 3650x this
  user's typical hour; largest single read 11,808 rows"), plus an
  `anomaly_alert` entry in the audit chain. Re-running is idempotent. Owners can
  revoke the flagged organization's grants on the dataset in one click.

**Evaluation on the seeded data** (user-hour level, 971 user-hours, 7 anomalous):

| Detector | Flagged | Precision | Recall | F1 |
|---|---|---|---|---|
| Isolation Forest | 10 | 0.70 | **1.00** | 0.82 |
| Threshold rule | 5 | 1.00 | 0.71 | 0.83 |

The rule catches the blatant patterns with no false alarms but misses both slow
exfiltrations; the Isolation Forest catches everything at the cost of three
false alarms for a human to dismiss. Raising contamination to 2% keeps recall at
1.0 but drops precision to 0.37.

## PII scanner (`ai/pii.py`)

```bash
python -m ai.pii path/to/file.csv
```

- **Input:** column names and up to 500 sampled rows.
- **Rules:** email, phone, Aadhaar, PAN, SSN, passport, payment cards (Luhn
  checked), IP addresses, dates; column-name hints (name, dob, address, income,
  diagnosis, ...); unique per-row codes are treated as identifiers.
- **NER:** spaCy `en_core_web_sm` finds person names and places in free text
  (falls back to rules if the model isn't installed).
- **Output per field:** suggested sensitivity (`pii`/`high`/`medium`/`low`),
  confidence, detected types with match rates, a masked preview, and a suggestion
  to encrypt. In the web app the owner reviews and confirms these before the
  dataset is published.
