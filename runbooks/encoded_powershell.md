# Runbook: Encoded PowerShell Command Execution

Severity: High. Detection: `detections/win_suspicious_powershell_encoded.yml`. Owner: SOC Tier 1, escalate to Tier 2.
ATT&CK: T1059.001, T1027.

Encoded commands are common enough that the first job is always decoding and
deciding whether it's real. Plenty of legit software wraps PowerShell in base64,
so I don't panic on the encoding alone. What moves it up the queue is the parent
process and the decoded intent. Phases below follow NIST 800-61r2.

## 1. Detection & Triage
- [ ] Pull the full `CommandLine` from the alert. Decode the base64 payload offline (do **not** execute):
  `echo '<b64>' | base64 -d | iconv -f UTF-16LE -t UTF-8` (PowerShell encodes UTF-16LE).
- [ ] Classify the decoded intent: download cradle, in-memory loader, recon, or benign admin.
- [ ] Check the parent process (`ParentImage`). Office apps, browsers, or `w3wp.exe` as parents sharply raise severity.
- [ ] Confirm against `false_positives`: SCCM, backup/EDR agents.

## 2. Containment
- [ ] If decoded payload is malicious: isolate the host via EDR network containment.
- [ ] Disable the executing user account if interactive logon and compromise suspected.
- [ ] Preserve volatile data before reboot (see Investigation).

## 3. Investigation
- [ ] Hunt for sibling activity from the same host/user (lateral pivot):
  ```spl
  index=endpoint host=<host> earliest=-4h
  | search Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\rundll32.exe"
  | table _time host User Image CommandLine ParentImage
  ```
- [ ] Extract IOCs from the decoded script: URLs, IPs, file paths, scheduled task / registry Run keys.
- [ ] Enrich external IOCs (VirusTotal / AbuseIPDB). Check for outbound connections to them in proxy/firewall logs.
- [ ] Determine persistence: query Sysmon EventCode 12/13 (registry) and 11 (file create) for the window.

## 4. Eradication & Recovery
- [ ] Kill malicious processes; remove dropped files and persistence (tasks, Run keys, services).
- [ ] Reset credentials for any account used on the host.
- [ ] Re-image if loader / C2 confirmed. Keep host isolated until validated clean.

## 5. Post-Incident
- [ ] Add confirmed IOCs to blocklists / threat intel.
- [ ] Tune the detection if a benign source produced the alert (allowlist by signed publisher, not by blanket exclusion).
- [ ] Document root cause and write up lessons learned.
