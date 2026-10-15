"""CSV parsing for dataset uploads."""

import csv
import io
import re

from .errors import AppError

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_ROWS = 20000


def normalize_header(name: str) -> str:
    n = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    if not n:
        n = "column"
    if n[0].isdigit():
        n = f"col_{n}"
    return n[:63]
//new parse function

def parse_csv(raw: bytes) -> tuple[list[str], list[str], list[dict[str, str | None]]]:
    """Return (original headers, normalized names, rows keyed by normalized name)."""
    if len(raw) > MAX_UPLOAD_BYTES:
        raise AppError(413, "File is larger than 5 MB", code="file_too_large")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise AppError(422, "The file must be UTF-8 encoded CSV", code="invalid_file") from e
    reader = csv.reader(io.StringIO(text))
    try:
        headers = next(reader)
    except StopIteration as e:
        raise AppError(422, "The CSV file is empty", code="invalid_file") from e
    names: list[str] = []
    for h in headers:
        base, n, i = normalize_header(h), normalize_header(h), 2
        while n in names:
            n, i = f"{base}_{i}", i + 1
        names.append(n)
    rows = []
    for line_no, values in enumerate(reader, start=2):
        if not any(v.strip() for v in values):
            continue
        if len(values) > len(names):
            raise AppError(
                422, f"Row {line_no} has more values than there are columns", code="invalid_file"
            )
        rows.append(
            {
                names[i]: (values[i].strip() or None) if i < len(values) else None
                for i in range(len(names))
            }
        )
        if len(rows) > MAX_ROWS:
            raise AppError(413, f"At most {MAX_ROWS} rows per upload", code="file_too_large")
    return headers, names, rows
