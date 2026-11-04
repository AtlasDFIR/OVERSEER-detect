# OVERSEER-detect

Splunk SPL detections paired with the incident-response runbooks I'd actually
work from when one of them fires. I started this to get reps on detection-as-code
after spending most of my day in the analyst seat, and it grew into a small
pipeline: every detection has a schema, a runbook, a test fixture, and CI that
checks all three line up.

The repo follows the path I think of as the detection lifecycle. A hunt starts
as a hypothesis, gets tuned until it's reliable, and then gets promoted into a
scheduled detection with a runbook attached. I built the tooling around that flow
rather than just dumping a folder of queries.

[![detections-ci](https://github.com/AtlasDFIR/OVERSEER-detect/actions/workflows/ci.yml/badge.svg)](../../actions)

## Layout

| Path | Contents |
|------|----------|
| `detections/` | Splunk SPL detections as validated YAML (schema is close to Sigma). |
| `runbooks/` | One IR runbook per detection, structured around NIST 800-61r2. |
| `hunts/` | Hypothesis-driven hunts that feed the detections. |
| `tests/` | JSON fixtures with a true-positive and a benign case per detection. |
| `scripts/` | Schema validator, test harness, ATT&CK coverage generator. |
| `integration/` | Real-Splunk end-to-end tests (Docker, HEC, REST). |
| `docs/` | IR process overview and the auto-generated coverage matrix. |
| `.github/workflows/` | Fast checks on every PR, plus the heavier Splunk run. |

## Detections

| Detection | Severity | ATT&CK | Platform |
|-----------|----------|--------|----------|
| Encoded PowerShell Command Execution | High | T1059.001, T1027 | Windows / Sysmon |
| Linux Reverse Shell Spawn | Critical | T1059.004, T1071.001 | Linux / auditd |
| AWS Console Login Without MFA | Medium | T1078.004, T1556.006 | AWS CloudTrail |
| Impossible Travel | High | T1078 | Windows auth |
| Kerberoasting - Anomalous TGS Requests | High | T1558.003 | Windows / Security |
| Suspicious Scheduled Task Creation | Medium | T1053.005 | Windows / Sysmon |
| DNS Tunneling / Exfiltration | High | T1048.003, T1071.004 | Network / DNS |
| Okta MFA Fatigue / Push Bombing | High | T1621, T1078.004 | Okta |

Full ATT&CK breakdown is in [`docs/COVERAGE.md`](docs/COVERAGE.md), which the
coverage script regenerates so it never drifts from the actual rules.

## How a detection earns its way in

I set a few gates so I couldn't get lazy and commit a half-finished rule:

1. It passes the schema validator (`scripts/validate_detections.py`).
2. Its fixture proves it fires on the true positive and stays quiet on the benign
   case (`scripts/test_detections.py`).
3. It links to a runbook that actually exists.
4. The regenerated coverage matrix is committed alongside it.

CI enforces all four, so a broken or undocumented rule fails the build.

## Running it locally

```bash
pip install -r requirements.txt
python3 scripts/validate_detections.py    # schema + referential integrity
python3 scripts/test_detections.py        # detection-logic regression tests
python3 scripts/coverage_report.py        # regenerate docs/COVERAGE.md
```

`make check` runs all three.

## Testing

There are two layers, and I added the second one after realizing the first
couldn't catch SPL mistakes.

The fast layer (`scripts/test_detections.py`, gated by `detections-ci`) evaluates
a documented subset of SPL in plain Python. It runs in seconds and catches logic
regressions, so it's what every PR goes through.

The integration layer (`integration/`, gated by `integration-ci`) stands up a
real Splunk 9.2 container, indexes a synthetic dataset over HEC, runs each
detection's actual SPL through the REST API, and checks the alert counts. This is
the one that catches what the subset can't: a wrong field name, a `stats`
grouping bug, a regex that behaves differently in Splunk's PCRE than in Python,
or an `appendcols` correlation I got slightly wrong.

```bash
make integration          # up + load + run  (needs Docker)
make integration-down     # tear down
```

The [`integration/README.md`](integration/README.md) has the architecture and the
steps to add a detection to that path.

## Adding a detection

1. Copy an existing YAML in `detections/` and edit it against
   [`detections/SCHEMA.md`](detections/SCHEMA.md).
2. Write a runbook from [`runbooks/_TEMPLATE.md`](runbooks/_TEMPLATE.md) and point
   the rule's `response:` field at it.
3. Add a fixture in `tests/` with at least one true positive and one benign event,
   then add a matching predicate in `scripts/test_detections.py`.
4. Run the three scripts above and commit the updated `docs/COVERAGE.md`.

## Notes and scope

Field names in the SPL follow common sourcetypes (Sysmon, WinEventLog, auditd,
CloudTrail). You'd map them to your own environment or CIM before deploying.

A few thresholds are deliberately blunt starting points. The Kerberoasting SPN
count and the DNS volume numbers in particular should be baselined against a few
weeks of normal traffic before going to production, otherwise they'll be noisy.

All sample data is synthetic. None of it came from a real environment.

## License

MIT, see [`LICENSE`](LICENSE).
