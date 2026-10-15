"""
PII scanner: suggests a sensitivity label per field and a masked preview.

Input: column names and sampled values from an uploaded dataset.
Method:
* pattern rules for emails, phone numbers, ID formats (Aadhaar, PAN, SSN,
  passport), payment cards (Luhn-checked), IP addresses and dates;
* column-name hints (``full_name``, ``dob``, ``address``, ``income`` ...);
* a lightweight NER model (spaCy ``en_core_web_sm``) for person names and
  places in free text. If spaCy or the model is not installed, the scanner
  falls back to rules only and says so in its output.

Output per field: suggested sensitivity (pii / high / medium / low), a
confidence, the detected types with match rates, and masked sample values.
The owner confirms the labels before the dataset is shared.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from typing import Any

# ---------------------------------------------------------------- patterns

PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "aadhaar": re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),
    "pan": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "passport": re.compile(r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "phone": re.compile(r"(?:\+\d{1,3}[ -]?)?(?:\(?\d{2,5}\)?[ -]?)?\d{3,5}[ -]?\d{4,5}\b"),
    "ip_address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "date": re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b"),
}

# Types that identify a person on their own -> pii
DIRECT_IDENTIFIERS = {
    "email",
    "aadhaar",
    "pan",
    "ssn",
    "passport",
    "credit_card",
    "phone",
    "person_name",
}
MASK_TOKENS = {
    "email": "[EMAIL]",
    "aadhaar": "[ID]",
    "pan": "[ID]",
    "ssn": "[ID]",
    "passport": "[ID]",
    "credit_card": "[CARD]",
    "phone": "[PHONE]",
    "ip_address": "[IP]",
    "date": "[DATE]",
    "person_name": "[PERSON]",
    "location": "[LOCATION]",
}

# Column-name hints: (regex on the normalized name, detected type, sensitivity)
NAME_HINTS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"(^|_)(full_?name|first_?name|last_?name|surname|name|student_name|"
            r"head_of_household|guardian|mother|father)($|_)"
        ),
        "person_name",
        "pii",
    ),
    (re.compile(r"(^|_)(e_?mail)($|_)"), "email", "pii"),
    (re.compile(r"(^|_)(phone|mobile|contact_?(no|number|phone)|tel)($|_)"), "phone", "pii"),
    (re.compile(r"(^|_)(dob|date_of_birth|birth_?date|birthday)($|_)"), "date_of_birth", "pii"),
    (
        re.compile(r"(^|_)(ssn|aadhaar|aadhar|pan|passport|national_?id|voter_?id|nid)($|_)"),
        "national_id",
        "pii",
    ),
    (
        re.compile(
            r"(^|_)(address|street|house|pincode|zip|postcode|gps|lat|lon|latitude|"
            r"longitude)($|_)"
        ),
        "location",
        "high",
    ),
    (
        re.compile(r"(^|_)(income|salary|wage|benefit|bank|account|iban|loan|debt)($|_)"),
        "financial",
        "high",
    ),
    (
        re.compile(
            r"(^|_)(diagnosis|disease|hiv|disability|mortality|pregnan|religion|caste|"
            r"ethnic|vulnerab|risk)"
        ),
        "special_category",
        "high",
    ),
    (
        re.compile(
            r"(^|_)(age|gender|sex|household|family_size|height|weight|attendance|"
            r"grade|marital)"
        ),
        "quasi_identifier",
        "medium",
    ),
]

SENSITIVITY_ORDER = {"low": 0, "medium": 1, "high": 2, "pii": 3}


@dataclass
class FieldReport:
    name: str
    suggested_sensitivity: str
    confidence: float
    detected: dict[str, float] = field(default_factory=dict)  # type -> share of sampled values
    reasons: list[str] = field(default_factory=list)
    masked_preview: list[Any] = field(default_factory=list)
    inferred_type: str = "text"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    fields: list[FieldReport]
    ner_available: bool
    rows_scanned: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": [f.to_dict() for f in self.fields],
            "ner_available": self.ner_available,
            "rows_scanned": self.rows_scanned,
        }


# ---------------------------------------------------------------- helpers


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        d = n * 2 if i % 2 == 1 else n
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def infer_type(values: Sequence[Any]) -> str:
    """Best-effort data type for a column of sampled values."""
    vals = [str(v).strip() for v in values if v is not None and str(v).strip() != ""]
    if not vals:
        return "text"

    def all_match(pattern: str) -> bool:
        return all(re.fullmatch(pattern, v, flags=re.IGNORECASE) for v in vals)

    if all_match(r"(true|false|yes|no|0|1)") and not all_match(r"\d+"):
        return "boolean"
    if all_match(r"[+-]?\d{1,15}"):
        return "integer"
    if all_match(r"[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?"):
        return "numeric"
    if all_match(r"\d{4}-\d{2}-\d{2}"):
        return "date"
    if all_match(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?"):
        return "timestamp"
    return "text"


@lru_cache(maxsize=1)
def _nlp():
    try:
        import spacy

        return spacy.load("en_core_web_sm", disable=["lemmatizer", "parser"])
    except Exception:
        return None


def ner_available() -> bool:
    return _nlp() is not None


def _detect_value(value: str) -> list[tuple[str, int, int]]:
    """(type, start, end) matches in one value, most specific types first."""
    spans: list[tuple[str, int, int]] = []
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in taken)

    for kind in (
        "email",
        "credit_card",
        "aadhaar",
        "pan",
        "ssn",
        "passport",
        "ip_address",
        "date",
        "phone",
    ):
        for m in PATTERNS[kind].finditer(value):
            a, b = m.span()
            if not free(a, b):
                continue
            text = m.group()
            digits = re.sub(r"\D", "", text)
            if kind == "credit_card" and not _luhn_ok(digits):
                continue
            if kind == "phone" and not (10 <= len(digits) <= 13):
                continue
            spans.append((kind, a, b))
            taken.append((a, b))
    return spans


def _mask(value: str, spans: Iterable[tuple[str, int, int]]) -> str:
    out = value
    for kind, a, b in sorted(spans, key=lambda s: s[1], reverse=True):
        out = out[:a] + MASK_TOKENS.get(kind, "[REDACTED]") + out[b:]
    return out


# ---------------------------------------------------------------- scanning


def scan_column(
    name: str, values: Sequence[Any], *, use_ner: bool = True, preview: int = 5
) -> FieldReport:
    norm = _normalize(name)
    texts = [str(v) for v in values if v is not None and str(v).strip() != ""]
    n = len(texts) or 1
    counts: Counter[str] = Counter()
    per_value_spans: list[list[tuple[str, int, int]]] = []

    for t in texts:
        spans = _detect_value(t)
        per_value_spans.append(spans)
        for kind in {s[0] for s in spans}:
            counts[kind] += 1

    nlp = _nlp() if use_ner else None
    inferred = infer_type(texts)
    if nlp is not None and inferred == "text" and texts:
        sample = texts[:200]
        for i, doc in enumerate(nlp.pipe(sample, batch_size=64)):
            kinds = set()
            for ent in doc.ents:
                kind = {
                    "PERSON": "person_name",
                    "GPE": "location",
                    "LOC": "location",
                    "FAC": "location",
                }.get(ent.label_)
                if kind and not any(
                    s[1] < ent.end_char and ent.start_char < s[2] for s in per_value_spans[i]
                ):
                    per_value_spans[i].append((kind, ent.start_char, ent.end_char))
                    kinds.add(kind)
            for kind in kinds:
                counts[kind] += 1

    detected = {k: round(c / n, 3) for k, c in counts.most_common()}
    reasons: list[str] = []
    sensitivity, confidence = "low", 0.5

    def raise_to(level: str, conf: float, why: str) -> None:
        nonlocal sensitivity, confidence
        reasons.append(why)
        if SENSITIVITY_ORDER[level] > SENSITIVITY_ORDER[sensitivity]:
            sensitivity, confidence = level, conf
        elif level == sensitivity:
            confidence = max(confidence, conf)

    # Value-based evidence (dates alone are not identifying)
    for kind, share in detected.items():
        if kind == "date":
            continue
        if share >= 0.3:
            level = "pii" if kind in DIRECT_IDENTIFIERS else "high"
            raise_to(
                level,
                min(0.99, 0.6 + share * 0.4),
                f"{share:.0%} of sampled values look like {kind.replace('_', ' ')}",
            )

    # Name-based evidence
    for pattern, kind, level in NAME_HINTS:
        if pattern.search(norm):
            conf = 0.75 if level == "pii" else 0.65
            if kind in detected or (kind == "date_of_birth" and "date" in detected):
                conf = 0.95
            raise_to(level, conf, f"column name suggests {kind.replace('_', ' ')}")
            break

    is_code = norm.endswith(("_id", "_code", "_no", "_number", "_ref"))
    if is_code and sensitivity != "pii" and len(set(texts)) >= 0.9 * n and n > 3:
        raise_to("pii", 0.6, "unique per row identifier (can link records to a person)")

    if not reasons:
        reasons.append("no personal data patterns found")
        confidence = 0.8 if texts else 0.3

    masked = [
        _mask(t, spans) if sensitivity in ("pii", "high") else t
        for t, spans in zip(texts[:preview], per_value_spans[:preview], strict=False)
    ]
    if sensitivity == "pii":
        masked = [
            m if m != t else "[REDACTED]" for m, t in zip(masked, texts[:preview], strict=False)
        ]

    return FieldReport(
        name=name,
        suggested_sensitivity=sensitivity,
        confidence=round(confidence, 2),
        detected=detected,
        reasons=reasons,
        masked_preview=masked,
        inferred_type=inferred,
    )


def scan_rows(
    rows: Sequence[Mapping[str, Any]], *, max_rows: int = 500, use_ner: bool = True
) -> ScanReport:
    """Scan a list of row dicts (e.g. a parsed CSV)."""
    sample = list(rows[:max_rows])
    columns: list[str] = []
    for r in sample:
        for k in r:
            if k not in columns:
                columns.append(k)
    fields = [scan_column(c, [r.get(c) for r in sample], use_ner=use_ner) for c in columns]
    return ScanReport(
        fields=fields, ner_available=ner_available() if use_ner else False, rows_scanned=len(sample)
    )


def main() -> int:
    import argparse
    import csv
    import json

    parser = argparse.ArgumentParser(description="Scan a CSV file for PII")
    parser.add_argument("csv_file")
    parser.add_argument("--no-ner", action="store_true")
    args = parser.parse_args()
    with open(args.csv_file, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(json.dumps(scan_rows(rows, use_ner=not args.no_ner).to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
