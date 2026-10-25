"""Dummy agent memory: a flat JSON file mimicking a Mongo collection.

Not real Mongo — a local stand-in with the same shape (insert_one/find) so swapping in a
real collection later is a drop-in change, not a rewrite.
"""
import json
import pathlib
import uuid
from datetime import datetime, timezone

MEMORY_FILE = pathlib.Path(__file__).parent / "memory.json"


def _load() -> list[dict]:
    if not MEMORY_FILE.exists():
        return []
    return json.loads(MEMORY_FILE.read_text())


def _save(records: list[dict]) -> None:
    MEMORY_FILE.write_text(json.dumps(records, indent=2))


def insert_one(finding: dict) -> dict:
    records = _load()
    finding = {
        "_id": str(uuid.uuid4()),
        "at": datetime.now(timezone.utc).isoformat(),
        **finding,
    }
    records.append(finding)
    _save(records)
    return finding


def upsert_one(finding: dict) -> dict:
    """Update the current copy of a finding instead of accumulating one per scan."""
    records = _load()
    evidence = finding.get("evidence") or {}
    identity = (
        finding.get("tool"),
        finding.get("endpoint"),
        evidence.get("advisoryId") or finding.get("summary"),
    )
    for index, record in enumerate(records):
        record_evidence = record.get("evidence") or {}
        record_identity = (
            record.get("tool"),
            record.get("endpoint"),
            record_evidence.get("advisoryId") or record.get("summary"),
        )
        if identity == record_identity:
            updated = {
                "_id": record["_id"],
                "at": datetime.now(timezone.utc).isoformat(),
                **finding,
            }
            records[index] = updated
            _save(records)
            return updated
    return insert_one(finding)


def find(**filters) -> list[dict]:
    records = _load()
    if not filters:
        return records
    return [r for r in records if all(r.get(k) == v for k, v in filters.items())]


def already_found(tool: str, endpoint: str) -> bool:
    """Dedup: has this tool already reported a finding for this endpoint?"""
    return len(find(tool=tool, endpoint=endpoint)) > 0
