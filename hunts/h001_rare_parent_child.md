# Hunt H001: Rare Parent and Child Process Relationships

**Hypothesis:** Adversary tradecraft produces parent/child process pairs that are
rare in the environment (for example `winword.exe` spawning `powershell.exe`). Frequency
analysis surfaces these against normal activity.

**ATT&CK:** T1059 (Command and Scripting Interpreter), T1106 (Native API)

## Query
```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval pair=ParentImage."  ->  ".Image
| stats count dc(host) as host_spread values(CommandLine) as sample_cmds by pair
| eventstats sum(count) as total
| eval pct=round(count/total*100,4)
| where pct < 0.1 AND host_spread < 5
| sort pct
```

## Triage
- Low `pct` and low `host_spread` means rare and localized, so investigate those first.
- Office/browser/PDF reader as parent of a script interpreter or LOLBin = high interest.
- Promote to detection if a specific pair is consistently malicious and benign-free.
