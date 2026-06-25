# Runbook: AWS Console Login Without MFA

Severity: Medium. Detection: `detections/aws_console_login_no_mfa.yml`. Owner: SOC Tier 1, loop in the Cloud team.
ATT&CK: T1078.004, T1556.006.

Medium severity because on its own it's a hygiene finding, not an incident. The
reason it's worth a runbook is that a password-only IAM login is often the first
step before something worse, so the value is in checking what the account did
next rather than just flagging the login. Steps follow NIST 800-61r2.

## 1. Detection & Triage
- [ ] Identify the IAM user, `sourceIPAddress`, and region from the CloudTrail event.
- [ ] Is this user a known break-glass / service account intentionally exempt from MFA? If yes and IP is expected, allowlist and close.
- [ ] Geolocate the source IP. Flag if outside expected corp/VPN ranges or in an unexpected country.

## 2. Containment
- [ ] If unexpected: attach a deny-all policy or disable the user's console password:
  `aws iam delete-login-profile --user-name <user>` (after evidence capture).
- [ ] Deactivate active access keys if abuse suspected:
  `aws iam update-access-key --user-name <user> --access-key-id <id> --status Inactive`.

## 3. Investigation
- [ ] Review all CloudTrail activity for the principal in the session window:
  ```spl
  index=cloud sourcetype="aws:cloudtrail" userIdentity.userName="<user>" earliest=-12h
  | stats count by eventName, sourceIPAddress, awsRegion
  | sort -count
  ```
- [ ] Look for privilege-escalation / persistence API calls: `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `CreateLoginProfile`, `UpdateAssumeRolePolicy`.
- [ ] Check for data-access / exfil signals: `GetObject` spikes, `ListBuckets`, `CreateSnapshot`, `ModifySnapshotAttribute` (sharing snapshots out).

## 4. Eradication & Recovery
- [ ] Rotate the user's password and all access keys.
- [ ] Enforce MFA via IAM policy condition (`aws:MultiFactorAuthPresent`).
- [ ] Revert any unauthorized IAM changes the principal made.

## 5. Post-Incident
- [ ] Confirm an SCP or IAM policy now denies console login without MFA org-wide.
- [ ] If a legitimate exempt account triggered this, add it to the detection allowlist lookup.
- [ ] Document and close.
