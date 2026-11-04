#!/usr/bin/env python3
"""Integration test runner: executes each detection's REAL SPL against a live
Splunk container loaded with the sample dataset, and asserts the alert row count
matches integration/expected/expected_alerts.json.

Unlike scripts/test_detections.py (a fast, dependency-free SPL-subset evaluator
used in the default CI), this runner validates the actual SPL end to end against
Splunk's search engine. It is gated behind the heavier `integration-ci` workflow.

Flow:
  1. Load integration/_indexed_events.json into Splunk via HEC (raw _time honored).
  2. For each detection, submit its `spl` as a oneshot search over a wide window.
  3. Count result rows and compare to the expected manifest.

Env:
  SPLUNK_HOST (default https://localhost:8089)
  SPLUNK_HEC  (default https://localhost:8088)
  SPLUNK_PASSWORD (default Changed123!)
  SPLUNK_HEC_TOKEN (default all-zeros)
"""
from __future__ import annotations
import json
import os
import sys
import time
import urllib3
from pathlib import Path

import requests
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent.parent
INTEG = ROOT / "integration"
DET_DIR = ROOT / "detections"

MGMT = os.environ.get("SPLUNK_HOST", "https://localhost:8089")
HEC = os.environ.get("SPLUNK_HEC", "https://localhost:8088")
PW = os.environ.get("SPLUNK_PASSWORD", "Changed123!")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "00000000-0000-0000-0000-000000000000")
AUTH = ("admin", PW)


def load_events() -> int:
    """Ship every sample event to HEC with its embedded _time and index."""
    events = (INTEG / "_indexed_events.json").read_text().splitlines()
    url = f"{HEC}/services/collector/event"
    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}
    sent = 0
    batch = []
    for line in events:
        line = line.strip()
        if not line:
            continue
        raw = json.loads(line)
        idx = raw.pop("index", "main")
        st = raw.pop("sourcetype", "_json")
        # Convert ISO _time to epoch for HEC's time field.
        t = raw.get("_time")
        epoch = None
        if t:
            epoch = time.mktime(time.strptime(t, "%Y-%m-%dT%H:%M:%S"))
        batch.append(json.dumps({
            "time": epoch,
            "index": idx,
            "sourcetype": st,
            "event": raw,
        }))
    payload = "\n".join(batch)
    r = requests.post(url, headers=headers, data=payload, verify=False, timeout=60)
    r.raise_for_status()
    sent = len(batch)
    print(f"Loaded {sent} events via HEC.")
    return sent


def wait_for_indexing(expected_min: int, timeout: int = 120) -> None:
    """Poll until the total indexed event count stabilizes."""
    deadline = time.time() + timeout
    last = -1
    while time.time() < deadline:
        n = run_search("| tstats count where index=* by index | stats sum(count) as c")
        total = int(n[0]["c"]) if n and n[0].get("c") else 0
        if total >= expected_min and total == last:
            print(f"Indexing settled at {total} events.")
            return
        last = total
        time.sleep(5)
    print(f"WARN: proceeding with {last} indexed events (expected >= {expected_min}).")


def run_search(spl: str, earliest: str = "-30d", latest: str = "now") -> list[dict]:
    """Run a blocking oneshot search, return parsed JSON result rows."""
    if not spl.strip().startswith("|"):
        spl = "search " + spl
    r = requests.post(
        f"{MGMT}/services/search/jobs/export",
        auth=AUTH, verify=False, timeout=120,
        data={
            "search": spl,
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
            "exec_mode": "oneshot",
        },
    )
    r.raise_for_status()
    rows = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "result" in obj:
            rows.append(obj["result"])
    return rows


def main() -> int:
    expected = json.loads((INTEG / "expected" / "expected_alerts.json").read_text())
    expected = {k: v for k, v in expected.items() if not k.startswith("_")}

    n = load_events()
    wait_for_indexing(expected_min=n)

    failures: list[str] = []
    passes = 0
    for det_file in sorted(DET_DIR.glob("*.yml")):
        doc = yaml.safe_load(det_file.read_text())
        rid = doc["id"]
        if rid not in expected:
            print(f"SKIP {det_file.name}: no expected entry")
            continue
        want = expected[rid]["expected_rows"]
        try:
            rows = run_search(doc["spl"])
            got = len(rows)
        except Exception as e:  # noqa: BLE001
            failures.append(f"{det_file.name}: search error: {e}")
            continue
        status = "PASS" if got == want else "FAIL"
        if got == want:
            passes += 1
        else:
            failures.append(f"{det_file.name}: expected {want} rows, got {got}")
        print(f"  [{status}] {expected[rid]['title']}: got {got}, want {want}")

    print(f"\n{passes} passed, {len(failures)} failed")
    if failures:
        print("\nFAILURES:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
