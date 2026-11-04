# Runbook: Suspicious Scheduled Task Creation

Severity: Medium. Detection: `detections/win_scheduled_task_persistence.yml`. Owner: SOC Tier 1, escalate to Tier 2.
ATT&CK: T1053.005.

Scheduled tasks are a favorite persistence spot because they survive reboots and
hide in plain sight. Installers and updaters create them constantly though, so
most of triage is separating normal software behavior from a task that launches an
interpreter or runs out of a temp path. Phases follow NIST 800-61r2.

## 1. Detection & Triage
- [ ] Capture the task name, the action (`task_cmd`), the host, and the creating user.
- [ ] Is the action a signed installer/updater writing to AppData/ProgramData? Cross-check against known software. If clearly benign, allowlist and close.
- [ ] High interest: task launches a script interpreter or LOLBin, runs from a user-writable temp path, or triggers `onlogon`/`onstart`.

## 2. Containment
- [ ] If malicious: disable the task (`schtasks /change /tn "<name>" /disable`) after capturing its full definition.
- [ ] Isolate the host if the task launches a loader or C2 callback.

## 3. Investigation
- [ ] Retrieve the full task XML and any referenced script/binary; hash and reputation-check it.
- [ ] Find what created the task by pivoting on the parent process around the creation time:
  ```spl
  index=endpoint host=<host> earliest=-2h
  | search Image="*\\schtasks.exe" OR CommandLine="*Register-ScheduledTask*"
  | table _time host User ParentImage CommandLine
  ```
- [ ] Look for sibling persistence (Run keys, services, WMI subscriptions) created in the same window.

## 4. Eradication & Recovery
- [ ] Delete the malicious task (`schtasks /delete /tn "<name>" /f`) and remove the referenced payload.
- [ ] Remove any co-located persistence; reset credentials for accounts used on the host.
- [ ] Re-image if a loader/C2 was confirmed.

## 5. Post-Incident
- [ ] Add payload hashes/paths to blocklists.
- [ ] Allowlist legitimate software that tripped the rule by publisher/path, not blanket exclusion.
- [ ] Document and close.
