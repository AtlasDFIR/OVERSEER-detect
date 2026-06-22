# Detection Rule Schema

Every detection in `detections/` is a YAML file validated by `scripts/validate_detections.py`
and exercised by the CI pipeline. The schema is intentionally close to Sigma so rules can be
ported, but the working query is native Splunk SPL.

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Stable UUIDv4. Never reused. |
| `title` | yes | Short human-readable name. |
| `status` | yes | `experimental`, `test`, or `production`. |
| `description` | yes | What the rule detects and why it matters. |
| `author` | yes | Detection engineer. |
| `created` / `modified` | yes | ISO-8601 dates. |
| `severity` | yes | `informational`, `low`, `medium`, `high`, `critical`. |
| `mitre` | yes | List of ATT&CK technique IDs (e.g. `T1059.001`). |
| `data_sources` | yes | Sourcetypes / indexes the rule depends on. |
| `spl` | yes | The Splunk search. Multi-line block scalar. |
| `schedule` | yes | `cron` + `earliest`/`latest` window. |
| `throttle` | no | Suppression window + fields to dedupe alerts. |
| `false_positives` | yes | Known benign triggers. |
| `response` | yes | Path to the runbook under `runbooks/`. |
| `references` | no | URLs / threat intel backing the logic. |
| `tests` | yes | Path to the test fixture under `tests/`. |
