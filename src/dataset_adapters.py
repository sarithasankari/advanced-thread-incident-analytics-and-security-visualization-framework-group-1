"""
Dataset Adapters Module
Provides adapters to ingest and map public datasets (NSL-KDD, UNSW-NB15, CICIDS2017)
into the common internal schema of the analytics framework.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any

class DatasetAdapter:
    """Detects and standardizes foreign cybersecurity dataset schemas to a common internal format."""

    SERVICE_PORT_MAP = {
        "http": 80, "https": 443, "ssl": 443, "ftp": 21, "ftp-data": 20,
        "ssh": 22, "telnet": 23, "smtp": 25, "dns": 53, "domain": 53,
        "dhcp": 67, "tftp": 69, "snmp": 161, "ldap": 389, "sql": 3306,
        "mysql": 3306, "oracle": 1521, "postgres": 5432, "rdp": 3389,
        "smb": 445, "netbios": 139, "irc": 194
    }

    ATTACK_TYPE_MAP = {
        # NSL-KDD classes
        "neptune": "DDoS", "back": "DDoS", "land": "DDoS", "pod": "DDoS", "smurf": "DDoS", "teardrop": "DDoS",
        "buffer_overflow": "Malware", "loadmodule": "Malware", "perl": "Malware", "rootkit": "Malware",
        "guess_passwd": "Brute Force", "ftp_write": "Brute Force", "imap": "Brute Force", "phf": "Phishing",
        "multihop": "Phishing", "warezmaster": "Malware", "warezclient": "Malware", "spy": "Malware",
        "satan": "Port Scanning", "ipsweep": "Port Scanning", "portsweep": "Port Scanning", "nmap": "Port Scanning",
        
        # UNSW-NB15 categories
        "fuzzers": "Port Scanning", "reconnaissance": "Port Scanning", "shellcode": "Malware",
        "backdoor": "Malware", "exploits": "Malware", "dos": "DDoS", "worms": "Malware",
        "generic": "Port Scanning", "analysis": "Port Scanning",
        
        # CICIDS2017 categories
        "ftp-patator": "Brute Force", "ssh-patator": "Brute Force", "dos slowloris": "DDoS",
        "dos slowhttptest": "DDoS", "dos hulk": "DDoS", "dos goldeneye": "DDoS", "heartbleed": "Malware",
        "web attack - brute force": "Brute Force", "web attack - xss": "SQL Injection",
        "web attack - sql injection": "SQL Injection", "infiltration": "Malware",
        "botnet": "Malware", "ddos": "DDoS", "portscan": "Port Scanning"
    }

    @classmethod
    def detect_dataset_type(cls, df: pd.DataFrame) -> str:
        """Determines the schema format by analyzing header keys."""
        cols = set(df.columns)
        
        # NSL-KDD columns sample
        if "protocol_type" in cols and "service" in cols and "src_bytes" in cols:
            return "nsl_kdd"
            
        # UNSW-NB15 columns sample
        if "srcip" in cols and "dstip" in cols and "attack_cat" in cols:
            return "unsw_nb15"
            
        # CICIDS2017 columns sample
        if "Destination Port" in cols or " Destination Port" in cols:
            # Check for label columns
            label_col = [c for c in cols if "label" in c.lower()]
            if label_col:
                return "cicids2017"
                
        return "unknown"

    @classmethod
    def adapt(cls, df: pd.DataFrame) -> pd.DataFrame:
        """Translates schema to internal database standard format."""
        dataset_type = cls.detect_dataset_type(df)
        
        if dataset_type == "nsl_kdd":
            return cls._adapt_nsl_kdd(df)
        elif dataset_type == "unsw_nb15":
            return cls._adapt_unsw_nb15(df)
        elif dataset_type == "cicids2017":
            return cls._adapt_cicids2017(df)
        else:
            raise ValueError("Unable to determine dataset schema. Verify columns align with NSL-KDD, UNSW-NB15, or CICIDS2017.")

    @classmethod
    def _adapt_nsl_kdd(cls, df: pd.DataFrame) -> pd.DataFrame:
        """Maps NSL-KDD format."""
        standardized_records = []
        base_time = datetime.now() - timedelta(days=30)
        
        # NSL-KDD might have 'class' or 'label'
        label_col = "class" if "class" in df.columns else "label"
        
        for idx, row in df.iterrows():
            # Mock IP addresses realistically based on classification
            is_anomaly = str(row.get(label_col, "normal")).strip().lower() != "normal"
            src_ip = f"172.16.1.{np.random.randint(50, 100)}" if is_anomaly else f"10.0.0.{np.random.randint(10, 250)}"
            dst_ip = f"10.100.1.{np.random.randint(1, 10)}"
            
            # Map port from service name
            service = str(row.get("service", "http")).lower()
            port = cls.SERVICE_PORT_MAP.get(service, 80)
            
            # Map attack type
            raw_attack = str(row.get(label_col, "normal")).lower()
            attack_type = cls.ATTACK_TYPE_MAP.get(raw_attack, "Port Scanning" if is_anomaly else "Port Scanning")
            if raw_attack == "normal":
                attack_type = "Port Scanning" # Fallback if normal to map to low-risk actions
                severity = "Low"
                status = "Detected"
                action_taken = "Logged"
            else:
                severity = "High" if row.get("num_failed_logins", 0) > 2 or attack_type in ["DDoS", "Malware"] else "Medium"
                status = "Blocked" if row.get("logged_in", 0) == 0 else "Detected"
                action_taken = "Blocked" if status == "Blocked" else "Alerted"

            # Create standard record
            standardized_records.append({
                "Timestamp": (base_time + timedelta(minutes=idx * 2)).strftime("%Y-%m-%d %H:%M:%S"),
                "Source_IP": src_ip,
                "Destination_IP": dst_ip,
                "Attack_Type": attack_type,
                "Protocol": str(row.get("protocol_type", "tcp")).upper(),
                "Port": port,
                "Severity": severity,
                "Status": status,
                "Country": "US", # default mock
                "Device": "IDS/IPS" if row.get("logged_in", 0) == 0 else "Firewall",
                "Action_Taken": action_taken,
                "Failed_Login_Count": int(row.get("num_failed_logins", 0)),
                "Session_Duration": float(row.get("duration", 0)) / 1000.0 # scale duration
            })
            
        return pd.DataFrame(standardized_records)

    @classmethod
    def _adapt_unsw_nb15(cls, df: pd.DataFrame) -> pd.DataFrame:
        """Maps UNSW-NB15 format."""
        standardized_records = []
        
        # Check keys
        attack_col = "attack_cat" if "attack_cat" in df.columns else "attack"
        
        for idx, row in df.iterrows():
            is_anomaly = int(row.get("label", 0)) == 1
            raw_attack = str(row.get(attack_col, "normal")).strip().lower()
            
            # Map attack type
            attack_type = cls.ATTACK_TYPE_MAP.get(raw_attack, "Port Scanning")
            if not is_anomaly or raw_attack in ["normal", "benign", ""]:
                attack_type = "Port Scanning"
                severity = "Low"
                status = "Detected"
                action_taken = "Logged"
            else:
                severity = "Critical" if attack_type in ["DDoS", "Malware"] else "Medium"
                status = "Blocked" if row.get("state", "CON") == "INT" else "Detected"
                action_taken = "Blocked" if status == "Blocked" else "Alerted"
                
            # Time stamp conversion
            epoch_time = float(row.get("Stime", datetime.now().timestamp()))
            timestamp = datetime.fromtimestamp(epoch_time).strftime("%Y-%m-%d %H:%M:%S")

            standardized_records.append({
                "Timestamp": timestamp,
                "Source_IP": str(row.get("srcip", "10.0.0.1")),
                "Destination_IP": str(row.get("dstip", "10.0.0.2")),
                "Attack_Type": attack_type,
                "Protocol": str(row.get("proto", "tcp")).upper()[:10],
                "Port": int(row.get("dsport", 80) if str(row.get("dsport")).isdigit() else 80),
                "Severity": severity,
                "Status": status,
                "Country": "US",
                "Device": "IDS/IPS" if row.get("service", "-") != "-" else "Firewall",
                "Action_Taken": action_taken,
                "Failed_Login_Count": 1 if row.get("is_ftp_login", 0) == 1 else 0,
                "Session_Duration": float(row.get("dur", 0.0))
            })
            
        return pd.DataFrame(standardized_records)

    @classmethod
    def _adapt_cicids2017(cls, df: pd.DataFrame) -> pd.DataFrame:
        """Maps CICIDS2017 format."""
        # Find labels by casing
        cols = {c.strip(): c for c in df.columns}
        
        label_col_name = cols.get("Label")
        src_ip_name = cols.get("Source IP")
        dst_ip_name = cols.get("Destination IP")
        dst_port_name = cols.get("Destination Port")
        protocol_name = cols.get("Protocol")
        timestamp_name = cols.get("Timestamp")
        duration_name = cols.get("Flow Duration")
        
        standardized_records = []
        for idx, row in df.iterrows():
            raw_label = str(row.get(label_col_name, "BENIGN")).strip().lower()
            is_anomaly = raw_label != "benign"
            
            # Map attack type
            attack_type = cls.ATTACK_TYPE_MAP.get(raw_label, "Port Scanning")
            if not is_anomaly:
                attack_type = "Port Scanning"
                severity = "Low"
                status = "Detected"
                action_taken = "Logged"
            else:
                severity = "Critical" if "ddos" in raw_label or "infiltration" in raw_label else "High"
                status = "Mitigated" if "patator" in raw_label else "Blocked"
                action_taken = "Blocked" if status == "Blocked" else "Alerted"
                
            # Parse Protocol codes (6 = TCP, 17 = UDP, 1 = ICMP)
            proto_val = int(row.get(protocol_name, 6))
            protocol = "TCP"
            if proto_val == 17:
                protocol = "UDP"
            elif proto_val == 1:
                protocol = "ICMP"
                
            # Parse duration from micro to seconds
            duration = float(row.get(duration_name, 0)) / 1000000.0
            
            # Format Timestamp (ensure standard format)
            ts_val = str(row.get(timestamp_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            try:
                # Handle common CICIDS date formats e.g. 14/07/2017 08:59
                ts_parsed = pd.to_datetime(ts_val)
                timestamp = ts_parsed.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            standardized_records.append({
                "Timestamp": timestamp,
                "Source_IP": str(row.get(src_ip_name, "192.168.1.1")),
                "Destination_IP": str(row.get(dst_ip_name, "192.168.1.2")),
                "Attack_Type": attack_type,
                "Protocol": protocol,
                "Port": int(row.get(dst_port_name, 80)),
                "Severity": severity,
                "Status": status,
                "Country": "US",
                "Device": "WAF" if int(row.get(dst_port_name, 80)) in [80, 443, 8080] else "Firewall",
                "Action_Taken": action_taken,
                "Failed_Login_Count": 0,
                "Session_Duration": duration
            })
            
        return pd.DataFrame(standardized_records)
