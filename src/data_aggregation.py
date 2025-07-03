import pandas as pd
import json
from api_integration import get_ip_reputation, get_malware_hash, get_domain_reputation

def aggregate_threat_data(ip, hash_value, domain):
    threat_list = []

    ip_data = get_ip_reputation(ip)
    if ip_data:
        threat_list.append({
            "Type": "IP",
            "Input": ip,
            "Details": json.dumps(ip_data)
        })

    malware_data = get_malware_hash(hash_value)
    if malware_data:
        flagged_results = {
            engine: result.get("result")
            for engine, result in malware_data.get("scans", {}).items()
            if result.get("detected")
        }

        threat_list.append({
            "Type": "Malware Hash",
            "Input": hash_value,
            "Details": json.dumps(flagged_results if flagged_results else {"Info": "No engines flagged this hash"})
        })

    domain_data = get_domain_reputation(domain)
    if domain_data:
        threat_list.append({
            "Type": "Domain",
            "Input": domain,
            "Details": json.dumps(domain_data)
        })

    df = pd.DataFrame(threat_list)
    return df

def save_to_csv(df, filename="data/threat_data.csv"):
    df.to_csv(filename, index=False)
    print(f"Threat data saved to {filename}")