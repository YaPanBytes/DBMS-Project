"""
Synthetic access-log generator.

Produces realistic dataset reads for the anomaly detector, with labelled
injected anomalies:

* ``bulk_export`` - one user pulls very large result sets many times within an
  hour, touching every field they can see;
* ``off_hours``   - a burst of reads between 01:00 and 04:59 UTC;
* ``slow_exfiltration`` - many medium-sized reads of every field within an
  hour, each below the rule-based thresholds (harder to catch).

Normal traffic: each actor (a user reading a dataset) makes a Poisson number of
reads on weekdays during working hours (09:00-17:59 UTC), with a log-normal
number of rows around that actor's typical volume and a subset of fields. A
few legitimate evening reads (19:00-21:59 UTC) are added as realistic noise.

Events are written to ``audit_log`` (the hash chain is maintained by the
database trigger) and the labels can be exported to CSV for evaluation.

    python -m ai.log_generator --days 30 --labels-out ai/data/labels.csv
"""

from __future__ import annotations

import csv
import random
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

NORMAL = "normal"
BULK_EXPORT = "bulk_export"
OFF_HOURS = "off_hours"
SLOW_EXFILTRATION = "slow_exfiltration"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ConsentLedger-Web/1.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) ConsentLedger-Web/1.0",
    "Mozilla/5.0 (X11; Linux x86_64) ConsentLedger-Web/1.0",
    "ConsentLedger-ETL/2.3 (scheduled report)",
]


@dataclass(frozen=True)
class Actor:
    """A user who legitimately reads a dataset (and which fields they may see)."""

    user_id: UUID
    dataset_id: UUID
    field_ids: tuple[UUID, ...]
    typical_rows: int = 120
    daily_rate: float = 3.0
    client_ip: str = "10.0.0.10"


@dataclass
class AccessEvent:
    user_id: UUID
    dataset_id: UUID
    field_ids: list[UUID]
    rows: int
    ts: datetime
    label: str = NORMAL
    client_ip: str = "10.0.0.10"
    user_agent: str = USER_AGENTS[0]
    query_text: str = field(default="")

    def __post_init__(self) -> None:
        if not self.query_text:
            self.query_text = f"access_dataset(limit={self.rows})"


def _poisson(rng: random.Random, lam: float) -> int:
    # Knuth's algorithm (fine for small lambda)
    limit, k, p = pow(2.718281828459045, -lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _workday_ts(rng: random.Random, day: datetime) -> datetime:
    return day.replace(
        hour=rng.randint(9, 17),
        minute=rng.randint(0, 59),
        second=rng.randint(0, 59),
        microsecond=rng.randint(0, 999_999),
    )


def generate_access_log(
    actors: Sequence[Actor],
    *,
    days: int = 30,
    now: datetime | None = None,
    n_bulk_exports: int = 2,
    n_off_hours: int = 3,
    n_slow_exfiltration: int = 2,
    seed: int = 7,
) -> list[AccessEvent]:
    """Generate normal reads for every actor plus injected anomalies."""
    if not actors:
        return []
    rng = random.Random(seed)
    now = (now or datetime.now(UTC)).astimezone(UTC)
    start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    events: list[AccessEvent] = []

    # ---- normal traffic
    for actor in actors:
        ua = rng.choice(USER_AGENTS)
        for d in range(days):
            day = start + timedelta(days=d)
            if day.weekday() >= 5 and rng.random() < 0.85:  # quiet weekends
                continue
            for _ in range(_poisson(rng, actor.daily_rate)):
                ts = _workday_ts(rng, day)
                if ts >= now:
                    continue
                rows = max(1, int(rng.lognormvariate(0, 0.45) * actor.typical_rows))
                k = rng.randint(1, max(1, len(actor.field_ids)))
                events.append(
                    AccessEvent(
                        user_id=actor.user_id,
                        dataset_id=actor.dataset_id,
                        field_ids=sorted(rng.sample(list(actor.field_ids), k), key=str),
                        rows=rows,
                        ts=ts,
                        client_ip=actor.client_ip,
                        user_agent=ua,
                    )
                )

    # ---- legitimate evening reads (noise, labelled normal)
    for actor in actors:
        for _ in range(rng.randint(0, 2)):
            day = start + timedelta(days=rng.randint(0, days - 1))
            ts = day.replace(hour=rng.randint(19, 21), minute=rng.randint(0, 59))
            if ts < now:
                events.append(
                    AccessEvent(
                        user_id=actor.user_id,
                        dataset_id=actor.dataset_id,
                        field_ids=sorted(
                            rng.sample(list(actor.field_ids), rng.randint(1, len(actor.field_ids))),
                            key=str,
                        ),
                        rows=max(1, int(rng.lognormvariate(0, 0.45) * actor.typical_rows)),
                        ts=ts,
                        client_ip=actor.client_ip,
                    )
                )

    # ---- injected anomalies (on distinct actors where possible)
    pool = list(actors)
    rng.shuffle(pool)

    for i in range(n_bulk_exports):
        actor = pool[i % len(pool)]
        day = start + timedelta(days=rng.randint(max(0, days - 10), days - 1))
        hour = day.replace(hour=rng.randint(10, 16), minute=0, second=0, microsecond=0)
        for q in range(rng.randint(18, 30)):
            ts = hour + timedelta(minutes=q * 2, seconds=rng.randint(0, 59))
            if ts >= now:
                break
            events.append(
                AccessEvent(
                    user_id=actor.user_id,
                    dataset_id=actor.dataset_id,
                    field_ids=sorted(actor.field_ids, key=str),
                    rows=rng.randint(4000, 12000),
                    ts=ts,
                    label=BULK_EXPORT,
                    client_ip="203.0.113.77",
                    user_agent="python-requests/2.31",
                    query_text="access_dataset(limit=1000, offset=*)",
                )
            )

    for i in range(n_off_hours):
        actor = pool[(i + n_bulk_exports) % len(pool)]
        day = start + timedelta(days=rng.randint(max(0, days - 14), days - 1))
        hour = day.replace(hour=rng.randint(1, 4), minute=0, second=0, microsecond=0)
        for q in range(rng.randint(6, 10)):
            ts = hour + timedelta(minutes=q * 6, seconds=rng.randint(0, 59))
            if ts >= now:
                break
            events.append(
                AccessEvent(
                    user_id=actor.user_id,
                    dataset_id=actor.dataset_id,
                    field_ids=sorted(actor.field_ids, key=str),
                    rows=int(actor.typical_rows * rng.uniform(1.5, 4)),
                    ts=ts,
                    label=OFF_HOURS,
                    client_ip="198.51.100.23",
                    user_agent=rng.choice(USER_AGENTS),
                )
            )

    for i in range(n_slow_exfiltration):
        actor = pool[(i + n_bulk_exports + n_off_hours) % len(pool)]
        day = start + timedelta(days=rng.randint(max(0, days - 12), days - 1))
        hour = day.replace(hour=rng.randint(10, 16), minute=0, second=0, microsecond=0)
        for q in range(rng.randint(10, 14)):
            ts = hour + timedelta(minutes=q * 4, seconds=rng.randint(0, 59))
            if ts >= now:
                break
            events.append(
                AccessEvent(
                    user_id=actor.user_id,
                    dataset_id=actor.dataset_id,
                    field_ids=sorted(actor.field_ids, key=str),
                    rows=rng.randint(900, 1500),
                    ts=ts,
                    label=SLOW_EXFILTRATION,
                    client_ip=actor.client_ip,
                    user_agent="python-requests/2.31",
                )
            )

    events.sort(key=lambda e: e.ts)
    return events


def write_events(session, events: Iterable[AccessEvent]) -> list[tuple[UUID, str]]:
    """Insert events into audit_log; returns (log_id, label) pairs."""
    from database.models import AuditAction, AuditLog

    written: list[tuple[AuditLog, str]] = []
    for e in events:
        log = AuditLog(
            user_id=e.user_id,
            dataset_id=e.dataset_id,
            field_ids=e.field_ids,
            action=AuditAction.SELECT,
            rows_affected=e.rows,
            query_text=e.query_text,
            client_ip=e.client_ip,
            user_agent=e.user_agent,
            ts=e.ts,
        )
        session.add(log)
        written.append((log, e.label))
    session.flush()
    return [(log.log_id, label) for log, label in written]


def save_labels(labels: Iterable[tuple[UUID, str]], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["log_id", "label"])
        writer.writerows((str(log_id), label) for log_id, label in labels)
    return path


def load_labels(path: str | Path) -> dict[str, str]:
    with Path(path).open() as f:
        return {row["log_id"]: row["label"] for row in csv.DictReader(f)}


def actors_from_grants(session) -> list[Actor]:
    """Build actors from the database: partners reading what they were granted,
    and owners reading their own datasets."""
    from sqlalchemy import select

    from database.models import ConsentGrant, Dataset, DatasetField, User, UserRole

    rng = random.Random(11)
    actors: list[Actor] = []

    grants = session.execute(
        select(ConsentGrant.grantee_org_id, ConsentGrant.dataset_id, ConsentGrant.field_id).where(
            ConsentGrant.revoked_at.is_(None)
        )
    ).all()
    by_org_ds: dict[tuple[UUID, UUID], list[UUID]] = {}
    for org_id, ds_id, f_id in grants:
        by_org_ds.setdefault((org_id, ds_id), []).append(f_id)

    users = session.scalars(select(User).where(User.is_active)).all()
    for (org_id, ds_id), fields in by_org_ds.items():
        for u in users:
            if u.org_id == org_id and u.role in (UserRole.PARTNER, UserRole.OWNER):
                actors.append(
                    Actor(
                        u.user_id,
                        ds_id,
                        tuple(fields),
                        typical_rows=rng.choice([40, 80, 150, 250]),
                        daily_rate=rng.uniform(1.5, 4),
                        client_ip=f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}",
                    )
                )

    datasets = session.scalars(select(Dataset)).all()
    fields_by_ds: dict[UUID, list[UUID]] = {}
    for f in session.scalars(select(DatasetField)).all():
        fields_by_ds.setdefault(f.dataset_id, []).append(f.field_id)
    for ds in datasets:
        owners = [u for u in users if u.org_id == ds.owner_org_id and u.role == UserRole.OWNER]
        for u in owners[:1]:
            actors.append(
                Actor(
                    u.user_id,
                    ds.dataset_id,
                    tuple(fields_by_ds.get(ds.dataset_id, [])),
                    typical_rows=rng.choice([100, 200, 400]),
                    daily_rate=rng.uniform(1, 3),
                    client_ip=f"10.1.{rng.randint(1, 20)}.{rng.randint(2, 250)}",
                )
            )
    return [a for a in actors if a.field_ids]


def main() -> int:
    import argparse

    from database.connection import session_scope

    parser = argparse.ArgumentParser(description="Generate synthetic access logs into audit_log")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--bulk", type=int, default=2, help="number of injected bulk exports")
    parser.add_argument(
        "--off-hours", type=int, default=3, help="number of injected off-hours bursts"
    )
    parser.add_argument("--slow", type=int, default=2, help="number of slow exfiltrations")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--labels-out", default="ai/data/labels.csv")
    args = parser.parse_args()

    with session_scope() as session:
        actors = actors_from_grants(session)
        events = generate_access_log(
            actors,
            days=args.days,
            n_bulk_exports=args.bulk,
            n_off_hours=args.off_hours,
            n_slow_exfiltration=args.slow,
            seed=args.seed,
        )
        labels = write_events(session, events)
    path = save_labels(labels, args.labels_out)
    n_anom = sum(1 for _, lbl in labels if lbl != NORMAL)
    print(f"Wrote {len(labels)} events ({n_anom} injected anomalies) for {len(actors)} actors")
    print(f"Labels: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
