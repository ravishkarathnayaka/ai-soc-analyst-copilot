import os
import json
from pydantic import BaseModel, Field
from typing import List

class TriageReport(BaseModel):
    alert_id: str
    verdict: str
    severity_score: int
    attack_narrative: str
    containment_checklist: List[str]
    investigation_steps: List[str]

def analyze_with_llm(enriched_data: dict) -> TriageReport:
    """Uses LLM (or automated heuristic fallback) to produce structured triage."""
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    
    if api_key:
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=api_key)
            prompt = f"""
            You are a Tier-1 SOC Security Analyst. Analyze this enriched alert:
            {json.dumps(enriched_data, indent=2)}
            
            Return a JSON object matching this schema:
            {{
                "alert_id": "{enriched_data['alert_id']}",
                "verdict": "True Positive | Suspicious | False Positive",
                "severity_score": <1-10>,
                "attack_narrative": "<2-3 sentence summary of adversary behavior>",
                "containment_checklist": ["step 1", "step 2", "step 3"],
                "investigation_steps": ["step 1", "step 2", "step 3"]
            }}
            """
            response = llm.invoke(prompt)
            # Parse JSON from LLM response
            import re
            json_match = re.search(r"\{.*\}", response.content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                return TriageReport(**data)
        except Exception as e:
            print(f"[!] LLM API error, falling back to rule engine: {e}")

    # Automated Rule-Based Heuristic Engine (works out of the box)
    iocs = enriched_data.get("iocs", {})
    alert_id = enriched_data.get("alert_id")
    
    if iocs.get("decoded_payload") and iocs["decoded_payload"] != "None":
        return TriageReport(
            alert_id=alert_id,
            verdict="True Positive (High Fidelity)",
            severity_score=9,
            attack_narrative=(
                f"Adversary executed obfuscated PowerShell on host {enriched_data.get('host')} using Base64 encoding. "
                f"The decoded payload attempts to download and execute an unauthorized remote script: '{iocs.get('decoded_payload')}'. "
                f"This matches MITRE ATT&CK T1059.001."
            ),
            containment_checklist=[
                f"Isolate endpoint '{enriched_data.get('host')}' from the network immediately.",
                f"Terminate offending PowerShell process PID and block extracted IPs/URLs: {iocs.get('extracted_urls')}.",
                f"Revoke active session tokens for user '{enriched_data.get('user')}' and initiate credential reset."
            ],
            investigation_steps=[
                "Review proxy and DNS logs for outbound beacons matching the extracted C2 IP/URL.",
                "Check Sysmon Event ID 11 for files dropped into Temp or Downloads by explorer.exe.",
                "Inspect parent process lineage to identify the initial access vector."
            ]
        )
    elif "run" in iocs.get("registry_key", "").lower():
        return TriageReport(
            alert_id=alert_id,
            verdict="True Positive (Persistence)",
            severity_score=8,
            attack_narrative=(
                f"Adversary modified the Windows CurrentVersion\\Run registry key on host {enriched_data.get('host')} "
                f"to establish reboot persistence for '{iocs.get('target_file')}'. "
                f"The command was spawned via cmd.exe, matching MITRE ATT&CK T1547.001."
            ),
            containment_checklist=[
                f"Delete malicious registry value '{iocs.get('registry_key')}'.",
                f"Quarantine the referenced binary: '{iocs.get('target_file')}'.",
                f"Kill active process instances associated with process ID {enriched_data.get('raw_alert', {}).get('details', {}).get('process_id', 'N/A')}."
            ],
            investigation_steps=[
                "Compute SHA256 hash of the target payload and query threat intelligence repositories.",
                "Search SIEM for other endpoints containing identical registry Run values.",
                "Review event logs for user logon activity preceding the registry modification."
            ]
        )
    else:
        return TriageReport(
            alert_id=alert_id,
            verdict="Suspicious",
            severity_score=5,
            attack_narrative="Activity requires analyst validation against corporate baseline.",
            containment_checklist=["Monitor host for anomalous process spawning."],
            investigation_steps=["Contact user to verify scheduled tasks or software installations."]
        )
