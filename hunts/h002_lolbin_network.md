# Hunt H002: LOLBins Making External Network Connections

**Hypothesis:** Living-off-the-land binaries (certutil, mshta, regsvr32, bitsadmin,
rundll32) rarely need to talk to the internet. When they do, it's often a download
or C2, so external connections from these binaries are worth a look.

ATT&CK: T1218 (System Binary Proxy Execution), T1071 (Application Layer Protocol).

## Query
```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| eval img=lower(Image)
| where match(img, "(certutil|mshta|regsvr32|bitsadmin|rundll32|msbuild)\.exe$")
| where NOT cidrmatch("10.0.0.0/8", DestinationIp)
    AND NOT cidrmatch("172.16.0.0/12", DestinationIp)
    AND NOT cidrmatch("192.168.0.0/16", DestinationIp)
| stats count values(DestinationIp) as dest_ips values(DestinationHostname) as dest_hosts
    by host, Image, User
| sort -count
```

## Triage
- Resolve destinations; check reputation (VirusTotal/AbuseIPDB).
- `certutil`/`bitsadmin` to a raw IP or newly registered domain = likely download cradle.
- Correlate with a preceding process-create of the same binary to recover the full command.
