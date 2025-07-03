import json
import pandas as pd
from api_integration import get_ip_reputation, get_malware_hash, get_domain_reputation

def print_alert(message):
    print(f"\n ALERT: {message}\n")

def main():
    results = []

    while True:
        print("\n === Threat Intelligence Menu ===")
        print("1. Check IP Reputation")
        print("2. Check Malware Hash")
        print("3. Check Domain Reputation")
        print("4. Exit")

        choice = input("Choose an option (1-4): ").strip()

        if choice == "1":
            ip = input("Enter the IP address: ").strip()
            ip_data = get_ip_reputation(ip)
            if ip_data:
                abuse_score = ip_data.get("data", {}).get("abuseConfidenceScore", 0)
                if abuse_score >= 75:
                    print(f"IP {ip} is VERY LIKELY MALICIOUS with an abuse score of {abuse_score}")
                elif abuse_score >= 50:
                    print(f"IP {ip} is suspicious with an abuse score of {abuse_score}")
                else:
                    print(f"IP {ip} appears clean with an abuse score of {abuse_score}")
                results.append({
                    "Type": "IP",
                    "Input": ip,
                    "Details": json.dumps(ip_data, indent=2)
                })

        elif choice == "2":
            hash_value = input("Enter the malware hash: ").strip()
            malware_data = get_malware_hash(hash_value)
            if malware_data:
                flagged = {
                    engine: res.get("result")
                    for engine, res in malware_data.get("scans", {}).items()
                    if res.get("detected")
                }
                if flagged:
                    print_alert(f"Malware hash {hash_value} was flagged by the following engines")
                    for engine, result in flagged.items():
                        print(f" - {engine}: {result}")
                else:
                    print(f"No engines flagged the hash {hash_value}")
                results.append({
                    "Type": "Malware Hash",
                    "Input": hash_value,
                    "Details": json.dumps(flagged if flagged else {"info": "Clean"}, indent=2)
                })
                
        elif choice == "3":
            domain = input("Enter the domain: ").strip()
            domain_data = get_domain_reputation(domain)
            if domain_data:
                threat_score = domain_data.get("pulse_info", {}).get("count", 0)
                if threat_score > 0:
                    print_alert(f"Domain {domain} is associated with known threats ({threat_score} pulses)")
                else:
                    print(f"Domain {domain} appears clean")
                results.append({
                    "Type": "Domain",
                    "Input": domain,
                    "Details": json.dumps(domain_data, indent=2)
                })

        elif choice == "4":
            break

        else:
            print("invaild choice. Try again.")

    if results:
        df = pd.DataFrame(results)
        df.to_csv("data/threat_data.csv", index=False)
        print("\n Threat data saved to data/threat_data.csv")
    else:
        print("No data was scanned. Exiting without saving")

if __name__ == "__main__":
    main()
