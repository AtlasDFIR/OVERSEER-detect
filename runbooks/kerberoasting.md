# Runbook: Kerberoasting

Severity: High. Detection: `detections/win_kerberoasting.yml`. Owner: SOC Tier 2 / IR.
ATT&CK: T1558.003, T1078.

The thing that took me a while to internalize on Kerberoasting is that the noisy
part (the ticket requests) and the dangerous part (offline cracking) happen at
different times. By the time you see the requests, the attacker may already have
the hashes. So the triage is about confirming intent fast and the recovery is
about rotating the service accounts before a crack lands. Phases follow NIST
800-61r2.

## 1. Detection & Triage
- [ ] Identify the requesting `Account_Name`, source `Client_Address`, and the list of SPNs requested.
- [ ] Is the source a vulnerability scanner or known SPN-discovery tool? Check the asset inventory for the IP. If yes, validate scope and likely close.
- [ ] Confirm RC4 (`0x17`) was requested. Modern clients default to AES, so a burst of RC4 across many SPNs is suspicious on its own.

## 2. Containment
- [ ] If the requesting account is compromised: disable it and revoke its sessions.
- [ ] Prioritize resetting passwords for any service accounts whose SPN tickets were requested. Those hashes may already be offline for cracking.

## 3. Investigation
- [ ] Pull the full SPN list the account requested and map each to its service account:
  ```spl
  index=auth sourcetype="WinEventLog:Security" EventCode=4769 Account_Name="<user>"
  | stats values(Service_Name) as spns by Account_Name, Client_Address
  ```
- [ ] Identify weak service accounts at risk: long-lived passwords, membership in privileged groups, no AES support.
- [ ] Determine how the requesting account was obtained (preceding suspicious logon, phishing, prior alert on the same host).

## 4. Eradication & Recovery
- [ ] Reset passwords on targeted service accounts to long (25+ char) random values; prefer gMSA where possible.
- [ ] Force AES on service accounts and disable RC4 where the environment allows.
- [ ] Remove unnecessary SPNs and trim service-account privileges.

## 5. Post-Incident
- [ ] Track that targeted service-account passwords were rotated.
- [ ] Tune the SPN-count threshold if a legitimate scanner is the source; allowlist that asset.
- [ ] Document and close.
