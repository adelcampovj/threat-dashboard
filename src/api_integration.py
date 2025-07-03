import requests
import json
import logging
import os

logging.basicConfig(
    filename = "logs/threat_dashboard.log",
    level = logging.INFO,
    format = "%(asctime)s - %(levelname)s - %(message)s"
)

def load_api_keys():
    try:
        with open("config.json", "r") as file:
            return json.load(file)
    except FileNotFoundError as e:
        print(f"Error: config.json not found: {str(e)}")
        logging.error("config.json not found.")
        return None
    
def get_ip_reputation(ip):
    try:
        keys = load_api_keys()
        if keys is None:
            raise ValueError("API keys nor loaded.")
        api_key = keys["abuseipdb"]
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {'ipAddress': ip}
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        logging.info(f"IP Reputation fetched for {ip}")
        return data
    except requests.HTTPError as http_err:
        print(f"HTTP error: {str(http_err)}")
        logging.error(f"HTTP Error: {str(http_err)}")
        return None
    except Exception as e:
        print(f"Error: {str(e)}")
        logging.error(f"Error: {str(e)}")
        return None
    
def get_malware_hash(hash_value):
    try:
        keys = load_api_keys()
        if keys is None:
            raise ValueError("API keys nor loaded")
        api_key = keys["virustotal"]
        url = f"https://virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey' : api_key,
            'resource' : hash_value
        }
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        logging.info(f"Malware hash report fetched for {hash_value}")
        return data
    except requests.HTTPError as http_err:
        print(f"HTTP Error: {str(http_err)}")
        logging.error(f"HTTP Error {str(http_err)}")
        return None
    except Exception as e:
        print(f"Error: {str(e)}")
        logging.error(f"Error: {str(e)}")
        return None
    
def get_domain_reputation(domain):
    try:
        keys = load_api_keys()
        if keys is None:
            raise ValueError("API keys not loaded.")
        api_key = keys["alienvault"]
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {'X-OTX-API-KEY': api_key}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        logging.info(f"Domain reputaton fetched for {domain}")
        return data
    except requests.HTTPError as http_err:
        print(f"HTTP Error {str(http_err)}")
        logging.error(f"Error HTTP: {str(http_err)}")
        return None
    except Exception as e:
        print(f"Error: {str(e)}")
        logging.error(f"Error: {str(e)}")
        return None
