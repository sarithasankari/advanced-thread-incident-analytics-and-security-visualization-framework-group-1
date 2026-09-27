"""
Synthetic Security Incident Data Generator
Generates a realistic, correlated cybersecurity dataset of 12,000 records
enriched with enterprise-level metadata fields for advanced anomaly detection.
"""

import os
import random
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

# Country coordinates and regions for geographic anomaly scores
COUNTRY_GEOGRAPHY: Dict[str, Dict[str, Any]] = {
    "US": {"lat": 37.0902, "lon": -95.7129, "regions": ["US-CA", "US-TX", "US-NY", "US-IL"]},
    "CN": {"lat": 35.8617, "lon": 104.1954, "regions": ["CN-BJ", "CN-SH", "CN-GD", "CN-JS"]},
    "RU": {"lat": 61.5240, "lon": 105.3188, "regions": ["RU-MOW", "RU-SPE", "RU-NVS", "RU-YEK"]},
    "DE": {"lat": 51.1657, "lon": 10.4515, "regions": ["DE-BY", "DE-BE", "DE-HE", "DE-NW"]},
    "GB": {"lat": 55.3781, "lon": -3.4360, "regions": ["GB-ENG", "GB-SCT", "GB-WLS", "GB-NIR"]},
    "IN": {"lat": 20.5937, "lon": 78.9629, "regions": ["IN-MH", "IN-KA", "IN-DL", "IN-TN"]},
    "JP": {"lat": 36.2048, "lon": 138.2529, "regions": ["JP-13", "JP-27", "JP-23", "JP-01"]},
    "BR": {"lat": -14.2350, "lon": -51.9253, "regions": ["BR-SP", "BR-RJ", "BR-MG", "BR-RS"]},
    "CA": {"lat": 56.1304, "lon": -106.3468, "regions": ["CA-ON", "CA-QC", "CA-BC", "CA-AB"]},
    "FR": {"lat": 46.2276, "lon": 2.2137, "regions": ["FR-IDF", "FR-PAC", "FR-ARA", "FR-GES"]}
}

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" # Scanners agent
]

USER_ROLES: List[str] = ["Admin", "Security Analyst", "DB Admin", "Developer", "HR Specialist", "Standard Employee"]
AUTH_METHODS: List[str] = ["Password", "MFA", "SSH Key", "API Key", "JWT"]

def generate_ip(pool: List[str], weight_distribution: np.ndarray = None) -> str:
    """Selects an IP from a pre-defined pool with given weights to simulate recurring attackers."""
    return random.choices(pool, k=1, weights=list(weight_distribution) if weight_distribution is not None else None)[0]

def generate_dataset(num_records: int = 12000, output_path: str = "data/raw/cyber_incidents_raw.csv") -> pd.DataFrame:
    """
    Generates a realistic synthetic security incident dataset.
    Injects correlations between attack types, protocols, ports, devices, severity,
    and advanced fields (session durations, regions, coords, roles, agents, auth methods).
    """
    print(f"Starting synthetic dataset generation of {num_records} records...")
    
    # Set seed for reproducibility
    random.seed(42)
    np.random.seed(42)

    # 1. Define country weights and geographical profiles
    countries = list(COUNTRY_GEOGRAPHY.keys())
    country_weights = [0.25, 0.15, 0.12, 0.08, 0.07, 0.08, 0.05, 0.04, 0.04, 0.12]
    
    # Attacker IP Pool (to allow repeating IPs for attack frequency analysis)
    num_attacker_ips = 300
    attacker_ips = [f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(num_attacker_ips)]
    # Make some IPs highly frequent (skewed distribution)
    ip_weights = np.random.zipf(1.5, size=num_attacker_ips)
    ip_weights = ip_weights / ip_weights.sum()

    # Destination IP Pool (Internal servers/subnets)
    num_dest_ips = 50
    dest_ips = [f"10.100.{random.randint(1, 10)}.{random.randint(1, 254)}" for _ in range(num_dest_ips)]

    attack_types = ["DDoS", "SQL Injection", "Brute Force", "Phishing", "Malware", "Port Scanning"]
    attack_weights = [0.25, 0.15, 0.20, 0.10, 0.15, 0.15]

    # Time frame: past 1 year
    end_time = datetime.now()
    start_time = end_time - timedelta(days=365)
    
    records = []

    for i in range(num_records):
        # Generate temporal distribution
        random_days = random.random() * 365
        timestamp = start_time + timedelta(days=random_days)
        hour_val = timestamp.hour
        night_modifier = hour_val in [23, 0, 1, 2, 3, 4, 5]

        # Select basic variables
        attack_type = random.choices(attack_types, weights=attack_weights, k=1)[0]
        src_ip = generate_ip(attacker_ips, ip_weights)
        dest_ip = random.choice(dest_ips)
        country = random.choices(countries, weights=country_weights, k=1)[0]
        
        # Pull geographics
        geo_profile = COUNTRY_GEOGRAPHY[country]
        # Add slight jitter to coords to make them look like different locations in that country
        lat = geo_profile["lat"] + np.random.uniform(-2.0, 2.0)
        lon = geo_profile["lon"] + np.random.uniform(-2.0, 2.0)
        region = random.choice(geo_profile["regions"])

        # Correlated values initialization
        protocol = "TCP"
        port = 80
        device = "Firewall"
        severity = "Medium"
        status = "Detected"
        action_taken = "Logged"
        failed_login_count = 0
        
        # Enterprise default fields
        session_duration = round(float(np.random.exponential(scale=120.0)), 2) # avg session length 2 minutes
        user_agent = random.choices(USER_AGENTS[:5], k=1)[0]
        user_role = random.choice(USER_ROLES)
        auth_method = random.choice(AUTH_METHODS)

        # Define logic based on attack types to inject correlation
        if attack_type == "DDoS":
            protocol = random.choice(["UDP", "TCP"])
            port = random.choice([80, 443, 53, 0])
            device = random.choice(["Firewall", "IDS/IPS"])
            severity = random.choice(["High", "Critical"]) if night_modifier or random.random() > 0.4 else "Medium"
            status = random.choices(["Detected", "Blocked", "Mitigated"], weights=[0.2, 0.5, 0.3], k=1)[0]
            action_taken = "Blocked" if status in ["Blocked", "Mitigated"] else "Alerted"
            session_duration = round(float(np.random.uniform(1.0, 15.0)), 2) # DDoS packets are short lived connections
            user_agent = USER_AGENTS[2] # Linux/curl type signature

        elif attack_type == "SQL Injection":
            protocol = "TCP"
            port = random.choice([80, 443, 3306, 8080])
            device = "WAF"
            severity = random.choice(["Medium", "High"])
            status = random.choices(["Blocked", "Mitigated", "Detected"], weights=[0.6, 0.3, 0.1], k=1)[0]
            action_taken = "Blocked" if status in ["Blocked", "Mitigated"] else "Alerted"
            session_duration = round(float(np.random.uniform(5.0, 45.0)), 2)
            user_role = "Standard Employee" # sql attacks normally mimic a standard compromise

        elif attack_type == "Brute Force":
            protocol = "TCP"
            port = random.choice([22, 3389, 445])
            device = "IDS/IPS"
            severity = "High" if random.random() > 0.5 else "Medium"
            failed_login_count = random.randint(3, 15) # higher failed logins
            status = random.choices(["Blocked", "Detected"], weights=[0.7, 0.3], k=1)[0]
            action_taken = "Blocked" if status == "Blocked" else "Alerted"
            session_duration = round(float(np.random.uniform(15.0, 180.0)), 2)
            auth_method = "Password"
            user_role = "Standard Employee"

        elif attack_type == "Phishing":
            protocol = "TCP"
            port = 443
            device = "IDS/IPS"
            severity = random.choice(["Low", "Medium"])
            status = random.choices(["Detected", "Mitigated", "Ignored"], weights=[0.5, 0.4, 0.1], k=1)[0]
            action_taken = "Alerted" if status == "Detected" else ("Logged" if status == "Ignored" else "Blocked")
            session_duration = round(float(np.random.exponential(scale=600.0)), 2) # users clicking links might sit on page
            auth_method = "JWT"
            user_role = "Standard Employee"

        elif attack_type == "Malware":
            protocol = "TCP"
            port = random.choice([443, 80, 4444, 8080])
            device = "Endpoint agent"
            severity = random.choice(["High", "Critical"])
            status = random.choices(["Blocked", "Mitigated", "Detected"], weights=[0.5, 0.4, 0.1], k=1)[0]
            action_taken = "Isolated" if random.random() > 0.5 else "Blocked"
            session_duration = round(float(np.random.exponential(scale=3600.0)), 2) # Malware command-and-control can persist hours
            user_role = "Developer" # developers have keys targeted by malware

        elif attack_type == "Port Scanning":
            protocol = random.choice(["TCP", "UDP"])
            port = random.randint(1024, 65535)
            device = "Firewall"
            severity = "Low"
            failed_login_count = 0
            status = "Detected"
            action_taken = "Logged"
            session_duration = round(float(np.random.uniform(0.1, 2.0)), 2) # port sweeps are milliseconds
            user_agent = USER_AGENTS[5] # Nmap Scanner signature

        # Adjust anomalies (outliers) randomly for 1% of the dataset
        if i % 100 == 0:
            # Inject anomaly: extremely long session
            session_duration = round(float(np.random.uniform(10000.0, 50000.0)), 2)
            # Inject anomaly: high failed logins on non-bruteforce
            if attack_type != "Brute Force":
                failed_login_count = random.randint(15, 30)

        # Construct record dictionary
        records.append({
            "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "Source_IP": src_ip,
            "Destination_IP": dest_ip,
            "Attack_Type": attack_type,
            "Protocol": protocol,
            "Port": port,
            "Severity": severity,
            "Status": status,
            "Country": country,
            "Device": device,
            "Failed_Login_Count": failed_login_count,
            "Action_Taken": action_taken,
            
            # Enterprise fields
            "Session_Duration": session_duration,
            "User_Agent": user_agent,
            "Latitude": round(lat, 4),
            "Longitude": round(lon, 4),
            "User_Role": user_role,
            "Auth_Method": auth_method,
            "Geo_Region": region
        })

    # Create DataFrame and export
    df = pd.DataFrame(records)
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Enhanced synthetic dataset saved successfully to '{output_path}'. Total shape: {df.shape}")
    return df

if __name__ == "__main__":
    generate_dataset()
