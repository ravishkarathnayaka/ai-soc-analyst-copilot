import os
import json
import glob
from enricher import enrich_alert
from ai_analyst import analyze_with_llm

def process_alerts():
    alert_files = glob.glob("alerts/*.json")
    if not alert_files:
        print("[!] No alert files found in alerts/ directory.")
        return

    print("=" * 70)
    print("      AI-POWERED SOC TIER-1 ANALYST COPILOT - TRIAGE RUNNER      ")
    print("=" * 70)

    for alert_file in alert_files:
        print(f"\n[+] Ingesting Alert: {alert_file}")
        with open(alert_file, "r") as f:
            raw_data = json.load(f)

        # 1. Enrichment
        enriched = enrich_alert(raw_data)
        print(f"    - Extracted Process : {enriched['iocs']['process_name']}")
        if enriched['iocs']['decoded_payload'] != "None":
            print(f"    - Decoded Payload   : {enriched['iocs']['decoded_payload'][:60]}...")
        if enriched['mitre_mapping']:
            print(f"    - MITRE ATT&CK      : {enriched['mitre_mapping'][0]['id']} ({enriched['mitre_mapping'][0]['technique']})")

        # 2. AI Triage
        report = analyze_with_llm(enriched)
        print(f"    - AI Verdict        : {report.verdict}")
        print(f"    - Severity Score    : {report.severity_score}/10")

        # 3. Generate Markdown Report
        report_filename = f"reports/INCIDENT_{report.alert_id}.md"
        with open(report_filename, "w", encoding="utf-8") as rf:
            rf.write(f"# SOC Incident Triage Report: {report.alert_id}\n\n")
            rf.write(f"**Timestamp:** {enriched.get('timestamp', 'N/A')}  \n")
            rf.write(f"**Host:** `{enriched.get('host')}` | **User:** `{enriched.get('user')}`  \n")
            rf.write(f"**Verdict:** **{report.verdict}** | **Severity:** `{report.severity_score}/10`  \n\n")
            
            rf.write("## 1. Attack Narrative\n")
            rf.write(f"{report.attack_narrative}\n\n")

            rf.write("## 2. Extracted Observables & IOCs\n")
            for k, v in enriched['iocs'].items():
                rf.write(f"* **{k}:** `{v}`\n")
            rf.write("\n")

            rf.write("## 3. Recommended Containment Checklist\n")
            for step in report.containment_checklist:
                rf.write(f"- [ ] {step}\n")
            rf.write("\n")

            rf.write("## 4. Next Investigation Steps\n")
            for step in report.investigation_steps:
                rf.write(f"1. {step}\n")

        print(f"    [✓] Incident Report Generated: {report_filename}")

    print("\n" + "=" * 70)
    print("Triage run complete! Check the reports/ folder for generated incident tickets.")
    print("=" * 70)

if __name__ == "__main__":
    process_alerts()
