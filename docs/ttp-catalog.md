# TTP Catalog (Starter)

This document maps scripts and playbooks to MITRE ATT&CK techniques. Each entry includes a brief description, required privileges, and cleanup notes. Expand this catalog as new techniques are added.

| Technique ID | Script/Playbook | Platform | Purpose | Privileges | Cleanup |
| --- | --- | --- | --- | --- | --- |
| T1059.004 | `scripts/linux/T1059_004.sh` | Linux | Demonstrates shell execution and command logging. | User | Remove temporary files in `/tmp/ttp-shell-*`. |
| T1059.001 | `scripts/windows/T1059_001.ps1` | Windows | Demonstrates PowerShell execution with transcript logging. | User | Delete transcript files and temporary payloads. |
| T1053.003 | `scripts/linux/T1053_003.sh` | Linux | Creates a cron job for persistence. | User (cron access) | Remove cron entry and related script. |
| T1105 | `scripts/windows/T1105.ps1` | Windows | Simulates ingress tool transfer using HTTP download. | User | Remove downloaded file and clear logs. |
| T1547.001 | `scripts/windows/T1547_001.ps1` | Windows | Sets a registry Run key for persistence. | Admin | Delete Run key and auxiliary files. |

## How to add a new technique
1. Create a script in `scripts/linux`, `scripts/windows`, or a dedicated Ansible role.
2. Add an entry to this table with a concise description and cleanup notes.
3. If orchestration is needed, add a playbook in `ansible/playbooks/` and reference the script.
4. Ensure the script respects `DRY_RUN` and logs actions to the standardized artifact path.

## Artifact conventions
- Logs: `./artifacts/logs/<technique>/<timestamp>.log`
- Downloads/tmp: `./artifacts/tmp/<technique>/`
- Transcripts (Windows): `./artifacts/transcripts/`
