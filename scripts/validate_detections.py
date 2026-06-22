#!/usr/bin/env python3
"""Validate detection YAML files against the repo schema.

Checks structural correctness, referential integrity (runbook + test files exist),
MITRE technique ID format, and basic SPL hygiene. Exit non-zero on any failure so
CI fails loudly.
"""
from __future__ import annotations
import re
import sys
import uuid
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
DET_DIR = ROOT / "detections"

REQUIRED = {
    "id", "title", "status", "description", "author", "created", "modified",
    "severity", "mitre", "data_sources", "spl", "schedule", "false_positives",
    "response", "tests",
}
STATUSES = {"experimental", "test", "production"}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

errors: list[str] = []
seen_ids: dict[str, str] = {}


def err(f: Path, msg: str) -> None:
    errors.append(f"{f.name}: {msg}")


def check(path: Path) -> None:
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        err(path, f"invalid YAML: {e}")
        return
    if not isinstance(doc, dict):
        err(path, "top-level YAML must be a mapping")
        return

    missing = REQUIRED - doc.keys()
    if missing:
        err(path, f"missing required fields: {', '.join(sorted(missing))}")

    rid = doc.get("id", "")
    try:
        uuid.UUID(str(rid))
    except (ValueError, TypeError):
        err(path, f"id is not a valid UUID: {rid!r}")
    if rid in seen_ids:
        err(path, f"duplicate id, also used by {seen_ids[rid]}")
    else:
        seen_ids[rid] = path.name

    if doc.get("status") not in STATUSES:
        err(path, f"status must be one of {sorted(STATUSES)}")
    if doc.get("severity") not in SEVERITIES:
        err(path, f"severity must be one of {sorted(SEVERITIES)}")

    for d in ("created", "modified"):
        v = doc.get(d)
        if not isinstance(v, date):
            err(path, f"{d} must be an ISO-8601 date (got {v!r})")

    mitre = doc.get("mitre") or []
    if not isinstance(mitre, list) or not mitre:
        err(path, "mitre must be a non-empty list")
    else:
        for t in mitre:
            if not MITRE_RE.match(str(t)):
                err(path, f"bad MITRE technique id: {t!r}")

    spl = doc.get("spl", "")
    if isinstance(spl, str) and spl.strip():
        if not re.search(r"\bindex\s*=", spl):
            err(path, "spl does not pin an index= (performance/scope risk)")
        if spl.lstrip().lower().startswith("|") is False and "search " in spl[:0]:
            pass
    else:
        err(path, "spl is empty")

    for ref_field in ("response", "tests"):
        ref = doc.get(ref_field)
        if ref and not (ROOT / ref).exists():
            err(path, f"{ref_field} points to missing file: {ref}")


def main() -> int:
    files = sorted(DET_DIR.glob("*.yml"))
    if not files:
        print("no detection files found", file=sys.stderr)
        return 1
    for f in files:
        check(f)
    if errors:
        print("DETECTION VALIDATION FAILED\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"OK: {len(files)} detections valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
