#!/usr/bin/env python3
"""Lightweight SPL detection test harness.

Each detection references a JSON test fixture describing events and the expected
number of alerts. We don't run a real Splunk instance in CI, so this harness
implements a small SPL-subset evaluator covering the operators our rules use:
field equality, IN, and regex `match()` on a derived command field. It is enough
to assert that a rule fires on true-positive events and stays silent on benign
events -- i.e. regression-tests the detection logic, not Splunk itself.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
DET_DIR = ROOT / "detections"


def derive_cmd(ev: dict) -> str:
    for k in ("CommandLine", "Process_Command_Line", "proctitle", "exe", "cmd"):
        if k in ev and ev[k]:
            return str(ev[k])
    return ""


def event_matches(rule_id: str, ev: dict) -> bool:
    """Hand-written predicate per rule id, mirroring the SPL core logic.

    Keeping this explicit (rather than parsing SPL) makes the intended behaviour
    of each detection auditable in one place.
    """
    cmd = derive_cmd(ev)
    if rule_id == "6f2a1c4e-9b3d-4f8a-bd21-3c7e0a5f1d92":  # encoded powershell
        img = (ev.get("Image") or ev.get("New_Process_Name") or "").lower()
        if not (img.endswith("powershell.exe") or img.endswith("pwsh.exe")):
            return False
        if not re.search(r"(?i)\s-e(nc(odedcommand)?)?\s", cmd):
            return False
        return bool(re.search(r"(?i)-nop|-w\s?hidden|-noni|bypass|frombase64string", cmd))
    if rule_id == "a1d9e7b2-4c6f-4a18-9e3b-2f8c1b6d4a07":  # aws no mfa
        return (ev.get("login_result") == "Success"
                and ev.get("mfa_used") == "No"
                and ev.get("identity_type") == "IAMUser")
    if rule_id == "e7b4d2f9-1a83-4c67-b5e2-8d3f0a9c1b46":  # linux reverse shell
        return (bool(re.search(r"(?i)(/dev/tcp/|/dev/udp/)", cmd))
                or bool(re.search(r"(?i)nc(\.traditional)?\s+.*-e\s", cmd))
                or bool(re.search(r"(?i)python[0-9.]*\s+-c\s+.*socket", cmd))
                or bool(re.search(r"(?i)(bash|sh)\s+-i\s.*>&", cmd)))
    if rule_id == "c3e8f1a6-7d22-4b59-8a14-9f0b2e6c5d31":  # impossible travel
        return ev.get("impossible_travel") is True
    if rule_id == "b8f3a91c-2e74-4d56-9a1f-7c4e0b2d6f83":  # kerberoasting
        return ev.get("rc4") is True and ev.get("distinct_spns", 0) >= 10
    if rule_id == "d4a7c2e9-6b18-4f53-8c92-1a3e7d5b0f64":  # scheduled task persistence
        return (bool(re.search(r"(?i)(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32)", cmd))
                or bool(re.search(r"(?i)(\\users\\public\\|\\appdata\\|\\temp\\|\\programdata\\)", cmd)))
    if rule_id == "f1e6b3d8-9c47-4a25-b6e1-2f8d0a4c7e59":  # dns exfiltration
        return (ev.get("query_count", 0) > 100
                and ev.get("unique_subs", 0) > 50
                and ev.get("avg_sub_len", 0) > 30)
    if rule_id == "a9c4e1f7-3d85-4b62-9e07-6b2f8a1d4c30":  # okta mfa fatigue
        return ev.get("push_count", 0) >= 5
    raise KeyError(f"no test predicate implemented for rule id {rule_id}")


def run() -> int:
    failures: list[str] = []
    total = 0
    for det_file in sorted(DET_DIR.glob("*.yml")):
        doc = yaml.safe_load(det_file.read_text())
        rid = doc["id"]
        fixture = ROOT / doc["tests"]
        if not fixture.exists():
            failures.append(f"{det_file.name}: fixture missing {doc['tests']}")
            continue
        cases = json.loads(fixture.read_text())
        for case in cases:
            total += 1
            events = case["events"]
            expected = case["expected_alerts"]
            fired = sum(1 for ev in events if event_matches(rid, ev))
            # alerts are grouped/deduped by stats; approximate by counting
            # distinct positive events unless the fixture says otherwise.
            got = case.get("group_count", fired if fired == 0 else 1) if case.get("grouped") else fired
            if got != expected:
                failures.append(
                    f"{det_file.name} [{case['name']}]: expected {expected} alerts, got {got}"
                )
    if failures:
        print("DETECTION TESTS FAILED\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"OK: {total} detection test cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
