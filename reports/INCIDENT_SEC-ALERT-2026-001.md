# SOC Incident Triage Report: SEC-ALERT-2026-001

**Timestamp:** 2026-10-10T07:35:12Z  
**Host:** `vm-windows-target` | **User:** `azureuser`  
**Verdict:** **True Positive (Persistence)** | **Severity:** `8/10`  

## 1. Attack Narrative
Adversary modified the Windows CurrentVersion\Run registry key on host vm-windows-target to establish reboot persistence for 'C:\Users\azureuser\AppData\Local\Temp\evil_payload.exe'. The command was spawned via cmd.exe, matching MITRE ATT&CK T1547.001.

## 2. Extracted Observables & IOCs
* **process_name:** `reg.exe`
* **parent_process:** `cmd.exe`
* **decoded_payload:** `None`
* **registry_key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater`
* **extracted_urls:** `[]`
* **extracted_ips:** `[]`
* **target_file:** `C:\Users\azureuser\AppData\Local\Temp\evil_payload.exe`

## 3. Recommended Containment Checklist
- [ ] Delete malicious registry value 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater'.
- [ ] Quarantine the referenced binary: 'C:\Users\azureuser\AppData\Local\Temp\evil_payload.exe'.
- [ ] Kill active process instances associated with process ID N/A.

## 4. Next Investigation Steps
1. Compute SHA256 hash of the target payload and query threat intelligence repositories.
1. Search SIEM for other endpoints containing identical registry Run values.
1. Review event logs for user logon activity preceding the registry modification.
