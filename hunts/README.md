# Threat Hunting Library

Hypothesis-driven hunts in Splunk SPL. Each one states the hypothesis, the ATT&CK
techniques it's after, the query, and how to triage what comes back. These are the
exploratory side of the repo. An analyst runs them by hand, and when one reliably
surfaces real activity without drowning you in noise, it earns promotion into a
scheduled detection under `detections/`.

That promotion path is the whole point. I didn't want hunts and detections to be
separate piles. A hunt is a detection that hasn't proven itself yet.

| Hunt | Hypothesis | ATT&CK |
|------|------------|--------|
| `h001_rare_parent_child.md` | Malware spawns processes through uncommon parent/child pairs | T1059, T1106 |
| `h002_lolbin_network.md` | LOLBins making external connections suggest C2 or download | T1218, T1071 |
| `h003_new_admin_logons.md` | A first-time admin logon to a host can signal lateral movement | T1078, T1021 |
