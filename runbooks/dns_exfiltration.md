# Runbook: DNS Tunneling / Exfiltration

Severity: High. Detection: `detections/dns_exfiltration.yml`. Owner: SOC Tier 2 / IR.
ATT&CK: T1048.003, T1071.004.

DNS tunneling slips past a lot of egress filtering because DNS is almost never
blocked, which is exactly why it's worth hunting. The catch is that some
legitimate services (CDNs, AV telemetry) also generate long algorithmic
subdomains, so the parent-domain reputation check is what keeps this from being
noise. Phases follow NIST 800-61r2.

## 1. Detection & Triage
- [ ] Capture the `src_ip`, the `parent_domain`, query volume, and average subdomain length.
- [ ] Reputation-check the parent domain. Is it a known CDN/AV/telemetry provider with algorithmic subdomains? If so it's likely benign, so validate and allowlist.
- [ ] Newly registered domain + long random subdomains + sustained volume from one host = strong tunneling signal.

## 2. Containment
- [ ] Sinkhole or block the parent domain at the resolver/firewall.
- [ ] Isolate the source host if a tunneling tool or active C2 is suspected. Preserve memory.

## 3. Investigation
- [ ] Characterize the traffic and confirm it's beaconing vs. bursty exfil:
  ```spl
  index=network src_ip=<host> query="*.<parent_domain>" earliest=-6h
  | timechart span=5m count
  ```
- [ ] On the host, find the process making the queries (Sysmon Event 22 / DNS client logs) and recover its binary.
- [ ] Estimate data volume moved: total query count times approximate bytes-per-label to gauge exfil scope.
- [ ] Identify what data the responsible process could access (sensitive shares, DB, credential stores).

## 4. Eradication & Recovery
- [ ] Kill the tunneling process; remove its binary and any persistence.
- [ ] Re-image if it's part of a broader intrusion; rotate credentials exposed on the host.
- [ ] Keep the domain blocked; add resolver-side detection for the parent domain.

## 5. Post-Incident
- [ ] Add the domain and tool hashes to threat intel.
- [ ] Assess whether confirmed data actually left the environment. If it did, engage the data-breach and notification process.
- [ ] Tune subdomain-length/volume thresholds against benign high-DNS services; allowlist them.
- [ ] Document and close.
