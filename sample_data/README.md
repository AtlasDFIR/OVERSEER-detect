# Sample Data

The JSON fixtures under `tests/` double as documented sample events for each
detection. They show the exact field shape a rule expects, which is handy when you
go to onboard the same log source into Splunk or adapt a rule to a different
sourcetype.

For the full end-to-end dataset that gets indexed into a real Splunk container,
see `integration/sample_events/` and `integration/generate_data.py`.

Everything here is synthetic. No real or sensitive data is included.
