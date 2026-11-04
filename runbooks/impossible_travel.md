# Runbook: Impossible Travel

Severity: High. Detection: `detections/win_impossible_travel.yml`. Owner: SOC Tier 1, escalate to Tier 2.
ATT&CK: T1078.

Impossible travel is high signal but it false-positives more than people expect,
mostly on VPNs and cloud jump boxes. I learned to rule those out first before
spending real cycles on it, because if you treat every hit as compromise you'll
burn the day chasing tunnels. Once the benign explanations are gone, treat it as
a credential or session theft. NIST 800-61r2 phases below.

## 1. Detection & Triage
- [ ] Note both logon locations, IPs, times, and the computed required travel speed.
- [ ] Rule out benign causes first: corporate VPN/proxy egress in another region, cloud RDP jump box, mobile carrier-grade NAT.
- [ ] Resolve both IPs. Is one a known VPN or hosting ASN? Is one the user's normal location?

## 2. Containment
- [ ] If compromise is plausible: revoke active sessions / tokens for the account and force re-authentication.
- [ ] Require a password reset + MFA re-enrollment.

## 3. Investigation
- [ ] Review the account's auth history and any actions from the suspicious location:
  ```spl
  index=auth Account_Name="<user>" earliest=-24h
  | iplocation Source_Network_Address
  | table _time Source_Network_Address Country City Logon_Type Status
  ```
- [ ] Check for mailbox rule creation, MFA method changes, or privileged group additions around the suspicious logon.
- [ ] Correlate with VPN connection logs to confirm/deny a tunnel explanation.

## 4. Eradication & Recovery
- [ ] Remove any attacker-created persistence (mail forwarding rules, app passwords, added MFA devices).
- [ ] Restore account to known-good config; confirm with the user out-of-band.

## 5. Post-Incident
- [ ] If a VPN/proxy caused a false positive, add the egress range to the detection's allowlist.
- [ ] Document and close; consider conditional-access tightening.
