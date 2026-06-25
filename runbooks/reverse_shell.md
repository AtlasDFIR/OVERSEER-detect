# Runbook: Linux Reverse Shell Spawn

Severity: Critical. Detection: `detections/linux_reverse_shell_spawn.yml`. Owner: SOC Tier 2 / IR.
ATT&CK: T1059.004, T1071.001.

This is the one I treat as an active intrusion from the first second and walk back
only if the evidence clears it, not the other way around. A shell that called out
means something already ran code on the box. The structure below follows the NIST
800-61r2 phases.

## 1. Detection & Triage
- [ ] Identify host, user, parent process, and the full command line.
- [ ] Extract the callback IP/port from the command (e.g. `/dev/tcp/<ip>/<port>`).
- [ ] If the parent is a web or app service (`nginx`, `php-fpm`, `java`, `node`), you're probably looking at an exploited internet-facing service. Escalate immediately.

## 2. Containment
- [ ] Isolate the host at the network layer (security group, NAC, or EDR containment). Do not power off, since you want to preserve memory.
- [ ] Block the callback IP at the perimeter firewall.
- [ ] Snapshot the volume / capture memory if IR tooling allows before remediation.

## 3. Investigation
- [ ] Confirm the outbound connection and find the listener side:
  ```spl
  index=network (src_ip=<host_ip> OR dest_ip=<callback_ip>) earliest=-2h
  | table _time src_ip src_port dest_ip dest_port bytes_out action
  ```
- [ ] Identify the initial access vector: review the web/app logs of the parent service for the request immediately preceding the spawn.
- [ ] Enumerate attacker actions on host: new users, SSH keys in `~/.ssh/authorized_keys`, cron entries, systemd units, modified `/etc/passwd`.
- [ ] Hunt for lateral movement: outbound SSH/SMB from the host to internal ranges after the callback time.

## 4. Eradication & Recovery
- [ ] Re-image from known-good. Patching the entry vector alone is insufficient once a shell landed.
- [ ] Rotate all credentials, keys, and tokens that lived on the host.
- [ ] Patch / virtual-patch the exploited service before returning to service.

## 5. Post-Incident
- [ ] Add callback IP and any tooling hashes to threat intel / blocklists.
- [ ] Root-cause the initial access; file findings for the service owner.
- [ ] Review whether the detection window/throttle caught it fast enough; tune if needed.
