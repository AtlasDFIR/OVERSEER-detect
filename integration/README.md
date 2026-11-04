# Integration Testing (Real Splunk)

This is the high-fidelity test path. It runs each detection's actual SPL against
a live Splunk container loaded with synthetic data, then checks that every rule
returns the number of alert rows I expect.

I added it after working with the fast harness for a while and realizing it had a
blind spot. The fast harness in `scripts/test_detections.py` only evaluates a
subset of SPL in Python, so it confirms my detection logic is sound but it never
actually touches Splunk. That means it can't catch a misspelled field, a `stats`
or `bin` grouping mistake, a regex that Splunk's PCRE engine handles differently
than Python's `re`, or a botched `appendcols` join. Those are exactly the bugs
that bite you in production, so this path exists to catch them.

## How it fits together

```
sample_events/*.json --[generate_data.py]--> _indexed_events.json
                                                   |
                                                   |  HEC (8088)
                                                   v
                                            Splunk 9.2 (container)
                                                   |
                                                   |  REST search (8089)
                                                   v
              run_integration_tests.py: run each detection's spl, count rows
                                                   |
                                                   v
                            compare against expected/expected_alerts.json
```

## Running it locally

You need Docker.

```bash
cd integration
export SPLUNK_PASSWORD=Changed123!
export SPLUNK_HEC_TOKEN=00000000-0000-0000-0000-000000000000

docker compose up -d
./wait_for_splunk.sh
python3 generate_data.py
pip install -r requirements.txt
python3 run_integration_tests.py

docker compose down -v   # tears down and removes volumes
```

Splunk Web is at http://localhost:8000 (admin / $SPLUNK_PASSWORD) if you want to
poke at the indexed data or step through a search by hand. I leaned on this a lot
while getting the expected row counts right.

## Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Single-instance Splunk 9.2 with HEC and REST exposed. |
| `splunk_setup/indexes.conf` | Pre-creates the `endpoint`, `auth`, `cloud`, `network` indexes. |
| `wait_for_splunk.sh` | Blocks until the API is up, then enables and tokenizes HEC. |
| `sample_events/*.json` | Seed events, a firing case and a benign case per rule. |
| `generate_data.py` | Expands the seeds and adds volumetric events like the DNS tunneling traffic. Seeded, so it's deterministic. |
| `run_integration_tests.py` | Loads the data, runs each detection's real SPL, checks row counts. |
| `expected/expected_alerts.json` | Expected alert count per detection, with a note on why. |

## Adding a detection to this path

1. Add seed events to the right `sample_events/<index>.json`. Include at least one
   event that should fire and one that should not.
2. Add an entry to `expected/expected_alerts.json` keyed by the detection `id`.
3. If the rule only fires at volume, extend `generate_data.py` to produce it.
4. Run it locally to confirm, then let `integration-ci` check it on the next PR.

## Why I kept both layers

It comes down to speed versus fidelity. Every PR gets the few-second Python check
so I'm not waiting on a container to know I broke something obvious. The Splunk
path runs on detection or integration changes and on a weekly schedule, because
spinning up Splunk and indexing data takes a couple of minutes and I didn't want
that in the inner loop. Splitting them this way is also closer to how a real
detection pipeline is set up, with quick logic checks separate from full
validation against the SIEM.
