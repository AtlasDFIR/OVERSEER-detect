# Runbook: <Title>

Severity: <sev>. Detection: `detections/<file>.yml`. Owner: SOC Tier 1/2.
ATT&CK: <technique ids>.

One or two sentences here on what makes this detection tricky or what you'd
check first. Keep it specific to the rule. Phases below follow NIST 800-61r2.
Work top to bottom and record everything in the case ticket.

## 1. Detection & Triage
- [ ] Confirm the alert is not a known false positive (see detection `false_positives`).
- [ ] Capture: host, user, source IP, timestamps, raw event.
- [ ] Set initial severity and assign.

## 2. Containment (short-term)
- [ ] Steps to stop spread without destroying evidence.

## 3. Investigation
- [ ] Pivot queries and enrichment.

## 4. Eradication & Recovery
- [ ] Remove the threat, restore to known-good.

## 5. Post-Incident
- [ ] Lessons learned, detection tuning, close.
