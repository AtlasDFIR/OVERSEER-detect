# Runbook: Okta MFA Fatigue / Push Bombing

Severity: High. Detection: `detections/okta_mfa_fatigue.yml`. Owner: SOC Tier 1, escalate to Tier 2.
ATT&CK: T1621, T1078.004.

The detail that matters most here is whether a push was accepted. A flood with no
accept is an attempt; a flood followed by a success means they're in, and the
account already had valid credentials for the attacker to trigger prompts at all.
Calling the user out of band early settles it fast. NIST 800-61r2 phases below.

## 1. Detection & Triage
- [ ] Identify the target user (`actor.alternateId`), the push volume, source IP(s), and whether a success followed (`PUSH_BOMB_THEN_SUCCESS` is urgent).
- [ ] Contact the user out-of-band: did they request these prompts? An unaware user receiving a flood = active attack with valid stolen credentials.
- [ ] Geolocate/reputation-check the source IP of the push requests.

## 2. Containment
- [ ] Clear the user's active Okta sessions and require re-authentication.
- [ ] If a push was accepted, treat the account as compromised and suspend it pending investigation.
- [ ] Reset the user's password (the attacker already has the current one to trigger prompts).

## 3. Investigation
- [ ] Review the user's full Okta event timeline around the burst:
  ```spl
  index=cloud sourcetype="OktaIM2:log" actor.alternateId="<user>" earliest=-6h
  | table _time eventType outcome.result client.ipAddress client.userAgent.rawUserAgent
  | sort _time
  ```
- [ ] If accepted, enumerate post-auth actions: app access, new device or MFA enrollment, profile or recovery-factor changes.
- [ ] Check for the same source IP targeting other users (spray + fatigue campaign).

## 4. Eradication & Recovery
- [ ] Remove any attacker-enrolled MFA factors or devices.
- [ ] Reset MFA and require re-enrollment from a trusted device.
- [ ] Revert unauthorized profile/recovery changes; revoke OAuth grants the attacker created.

## 5. Post-Incident
- [ ] Recommend control changes: number-matching / verified push, rate-limiting, and disabling simple push approval.
- [ ] Block the source IP/ASN; add to threat intel.
- [ ] Brief the user on MFA fatigue; document and close.
