# SOC Incident Response Process

The runbooks in this repo are built around the NIST SP 800-61r2 incident response
lifecycle. This doc is the overview. Each runbook is the technique-specific version
of the same flow.

## The lifecycle

I think of it as four phases that loop:

1. Preparation. The logging coverage, detections, and runbooks are in place before
   anything happens. That's most of what this repo is.
2. Detection and analysis. A scheduled detection fires and the analyst triages it
   using section 1 of the linked runbook.
3. Containment, eradication, and recovery. Sections 2 through 4 of the runbook.
4. Post-incident activity. Section 5: lessons learned and detection tuning, which
   feeds back into preparation for next time.

The loop matters. Most of the tuning ideas in these runbooks came from a previous
alert that was noisier than it should have been.

## Severity and escalation

| Severity | Examples | Initial owner | Escalate to |
|----------|----------|---------------|-------------|
| Critical | Active reverse shell, confirmed ransomware | Tier 2 / IR | IR lead, management |
| High | Encoded PowerShell with a malicious payload, impossible travel | Tier 1, then Tier 2 | Tier 2 |
| Medium | Login without MFA | Tier 1 | Cloud / IT |
| Low / Info | Policy hygiene findings | Tier 1 | n/a |

## The detection side of the loop

On the engineering side, a detection has its own lifecycle before it ever fires in
production:

```
hypothesis --> hunt (hunts/) --> tune --> promote --> detection (detections/)
                                                          |
                                              status: experimental
                                                   |    test
                                                   v    production
                                            scheduled in the SIEM
```

A rule only reaches `production` after its test fixtures pass in CI and a runbook
exists for it. The validator enforces the runbook link and CI enforces the tests,
so I can't accidentally ship a detection with nobody home when it fires.
