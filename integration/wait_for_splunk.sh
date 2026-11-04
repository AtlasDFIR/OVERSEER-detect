#!/usr/bin/env bash
# Block until Splunk's management API is responsive, then enable + configure HEC.
set -euo pipefail

SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-Changed123!}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-00000000-0000-0000-0000-000000000000}"
MGMT="https://localhost:8089"
MAX=40

echo "Waiting for Splunk management API..."
for i in $(seq 1 "$MAX"); do
  if curl -fsk -u "admin:${SPLUNK_PASSWORD}" "${MGMT}/services/server/info" >/dev/null 2>&1; then
    echo "Splunk is up (attempt ${i})."
    break
  fi
  if [ "$i" -eq "$MAX" ]; then
    echo "ERROR: Splunk did not become ready in time." >&2
    exit 1
  fi
  sleep 10
done

echo "Enabling HTTP Event Collector..."
curl -fsk -u "admin:${SPLUNK_PASSWORD}" -X POST \
  "${MGMT}/servicesNS/nobody/splunk_httpinput/data/inputs/http/http" \
  -d "disabled=0" >/dev/null || true

# Create a token with a known value so the loader can authenticate.
curl -fsk -u "admin:${SPLUNK_PASSWORD}" -X POST \
  "${MGMT}/servicesNS/nobody/splunk_httpinput/data/inputs/http" \
  -d "name=ingest" \
  -d "token=${HEC_TOKEN}" \
  -d "index=endpoint" \
  -d "indexes=endpoint,auth,cloud,network" >/dev/null 2>&1 || \
  echo "(HEC token 'ingest' may already exist - continuing)"

echo "HEC ready."
