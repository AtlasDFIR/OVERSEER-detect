# Hunt H003: First-Time Admin Logons to a Host

**Hypothesis:** An administrative account logging on to a host it has never
accessed before can indicate lateral movement using stolen credentials.

ATT&CK: T1078 (Valid Accounts), T1021 (Remote Services).

## Query
```spl
index=auth sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type IN (3,9,10)
| search Account_Name IN ("*admin*","*adm_*","*-da","*svc-*")
| stats earliest(_time) as first_logon by Account_Name, ComputerName
| eval is_new=if(first_logon >= relative_time(now(), "-24h"), 1, 0)
| where is_new=1
| convert ctime(first_logon)
| sort first_logon
```

## Triage
- Cross-reference with change tickets / expected admin activity.
- New admin logon shortly after an alert on the same host = strong lateral-movement signal.
- Pivot to what the account did post-logon (process creation, service install, share access).
