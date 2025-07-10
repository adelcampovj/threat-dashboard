![threat-dashboard](https://img.shields.io/badge/status-Ready%20for%20Use-brightgreen)
![Python](https://img.shields.io/badge/python-3.x-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)

# Threat Dashboard

A terminal based tool for analyzing IP addresses, malware hashes, and domain reputations using public threat intelligence APIs

If you have any questions about using this threat dashboard, or just want to connect, feel free to reach out:

- [LinkedIn](https://www.linkedin.com/in/antonio-del-campo/)

### Features
* Real-time IP reputation checks via AbuseIPDB
* Malware hash scans through VirusTotal
* Domain reputation lookups via AlienVault OTX
* Auto-export results to clean CSV files
* Prints threat alerts directly to terminal

## Screenshots

### Main Menu
![menu](images/screenshot_menu.png)

### Threat Alert
![alert](images/screenshot_alert.png)

### CSV Output 
![csv](images/screenshot_csv.png)

### Logs Output
![logs](images/screenshot_logs.png)

## Installation

This is a Python based application. To install and run it:

```bash
git clone https://github.com/adelcampovj/threat-dashboard.git
cd threat-dashboard
python3 -m venv env
source env/bin/activate        # On Windows: .\env\Scripts\activate
pip install -r requirements.txt
```

Then, rename `config_sample.json` to `config.json`, and paste your own API keys like this:

```json
{
  "abuseipdb": "YOUR_ABUSEIPDB_KEY",
  "virustotal": "YOUR_VIRUSTOTAL_KEY",
  "alienvault": "YOUR_ALIENVAULT_KEY"
}
```

## Usage

Run the program using:

```bash
python src/dashboard.py
```

Follow the prompts:

1. Choose the scan type (IP, Hash, Domain)
2. Enter the input value when asked
3. Review results and alerts in the terminal
4. Exit to auto-save results

Output files:
- `data/threat_data.csv` – stores all scanned entries
- `logs/threat_dashboard.log` – records API and system activity

If you see import warnings in VS Code, make sure your virtual environment is active and the Python interpreter is selected correctly.
