import json
import base64
import re

def decode_powershell_base64(command_line: str) -> str:
    """Detects and decodes obfuscated Base64 UTF-16LE PowerShell commands."""
    match = re.search(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", command_line, re.IGNORECASE)
    if match:
        encoded_str = match.group(1)
        try:
            decoded_bytes = base64.b64decode(encoded_str)
            return decoded_bytes.decode('utf-16le', errors='ignore').strip()
        except Exception:
            return ""
    return ""

def enrich_alert(alert_data: dict) -> dict:
    """Extracts observables, decodes payloads, and maps to MITRE ATT&CK."""
    details = alert_data.get("details", {})
    cmd = details.get("command_line", "")
    target_obj = details.get("target_object", "")
    decoded_cmd = decode_powershell_base64(cmd) if cmd else ""

    # Extract IOCs and endpoints
    all_cmd_text = f"{cmd} {decoded_cmd}"
    urls = re.findall(r'https?://[^\s\'"]+', all_cmd_text)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', all_cmd_text)

    iocs = {
        "process_name": details.get("image", "").split("\\")[-1] if details.get("image") else "",
        "parent_process": details.get("parent_image", "").split("\\")[-1] if details.get("parent_image") else "",
        "decoded_payload": decoded_cmd if decoded_cmd else "None",
        "registry_key": target_obj if target_obj else "None",
        "extracted_urls": list(set(urls)),
        "extracted_ips": list(set(ips)),
        "target_file": details.get("details", "None")
    }

    # MITRE ATT&CK Mapping
    mitre_techniques = []
    if "powershell" in details.get("image", "").lower() or (cmd and "powershell" in cmd.lower()):
        mitre_techniques.append({
            "id": "T1059.001",
            "technique": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution"
        })
    if "currentversion\\run" in target_obj.lower():
        mitre_techniques.append({
            "id": "T1547.001",
            "technique": "Boot or Logon Autostart Execution: Registry Run Keys",
            "tactic": "Persistence"
        })

    return {
        "alert_id": alert_data.get("alert_id"),
        "timestamp": alert_data.get("timestamp"),
        "host": alert_data.get("host"),
        "user": alert_data.get("user"),
        "description": alert_data.get("description"),
        "iocs": iocs,
        "mitre_mapping": mitre_techniques
    }
