#!/usr/bin/env python3
"""Expand the seed sample-event files into the full event set for indexing.

Most detections fire on a handful of hand-written events. Two need volume:
  - DNS exfiltration needs >100 long high-entropy subdomains from one host.
  - (Kept extensible for any future volumetric rule.)

This script reads integration/sample_events/*.json (newline-delimited JSON),
adds the generated volumetric events, and writes a single combined
integration/_indexed_events.json ready for the HEC loader. Keeping generation
explicit and seeded makes the dataset deterministic and reviewable.
"""
from __future__ import annotations
import json
import random
import string
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "sample_events"
OUT = ROOT / "_indexed_events.json"

random.seed(1337)  # deterministic


def rand_label(n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def dns_tunnel_events(count: int = 150) -> list[dict]:
    """Generate high-volume long-subdomain DNS queries for one host."""
    events = []
    base_min = 0
    for i in range(count):
        # ~45-char random subdomain -> well over the 30-char threshold
        sub = rand_label(45)
        sec = f"{base_min // 60:02d}:{base_min % 60:02d}"
        events.append({
            "_time": f"2026-06-20T16:{sec}",
            "index": "network",
            "sourcetype": "stream:dns",
            "src_ip": "10.0.0.55",
            "query": f"{sub}.tunnel.evil-c2.com",
        })
        base_min += 1 if i % 3 == 0 else 0  # cluster within 10-min bins
    return events


def main() -> int:
    combined: list[str] = []
    for f in sorted(SRC.glob("*.json")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if line:
                combined.append(line)
    # append generated volumetric events
    for ev in dns_tunnel_events():
        combined.append(json.dumps(ev))

    OUT.write_text("\n".join(combined) + "\n")
    print(f"wrote {OUT.name}: {len(combined)} events "
          f"({len(combined) - sum(1 for _ in [])} indexed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
