"""
Alerting and Playbook Mitigation Module
Triggered on High Risk threat classifications.
Generates alert PDFs, sends mock emails, creates mock ticketing systems (Jira/ServiceNow),
and writes database trace logging.
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

# Path configuration for direct execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.report_generator import generate_pdf_prediction_report
from src.database_manager import db_add_audit_log
from src.utils.logger import get_logger, get_auth_logger

logger = get_logger("alerting_system")
auth_logger = get_auth_logger()

def trigger_high_risk_alert(incident_data: Dict[str, Any], pred_result: Dict[str, Any], db: Optional[Session] = None) -> Dict[str, Any]:
    """
    Executes defensive playbooks for critical alerts:
    1. Generates compliance PDF case file.
    2. Writes a warning audit log to the database.
    3. Simulates sending an encrypted alert email to security responders.
    4. Generates a mock ticketing system incident report (JSON).
    """
    source_ip = incident_data.get("Source_IP", "Unknown Attacker")
    dest_ip = incident_data.get("Destination_IP", "Unknown Target")
    attack_type = incident_data.get("Attack_Type", "Exploit")
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    logger.warning(f"⚠️ HIGH RISK THREAT INSTANTIATED: {attack_type} from {source_ip} targeting {dest_ip}")
    
    # Ensure alerts storage directory exists
    os.makedirs("alerts", exist_ok=True)
    
    # 1. Generate Investigation PDF Report
    pdf_path = f"alerts/alert_{timestamp_str}_{source_ip.replace('.', '_')}.pdf"
    try:
        generate_pdf_prediction_report(incident_data, pred_result, pdf_path)
        logger.info(f"Compliance case-file PDF compiled at: {pdf_path}")
    except Exception as e:
        logger.error(f"Failed to generate case-file PDF for alert: {str(e)}")
        pdf_path = "Failed to generate"

    # 2. Database Logs
    if db is not None:
        try:
            db_add_audit_log(
                db=db,
                username="SYSTEM_ML_CLASSIFIER",
                action=f"CRITICAL TRIGGER: High Risk {attack_type} detected. IP: {source_ip} -> {dest_ip}. PDF compiled at {pdf_path}",
                ip_address=source_ip
            )
            logger.info("Compliance Audit Log successfully committed to DB.")
        except Exception as e:
            logger.error(f"Failed to write alert database audit log: {str(e)}")

    # 3. Simulate Email Alerting
    mock_email = f"""
    ========================================================================
    SEC-OPS CRITICAL ALERT EMAIL SIMULATION
    ========================================================================
    From: {settings.ALERT_EMAIL_SENDER}
    To: {settings.ALERT_EMAIL_RECEIVER}
    Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S')}
    Subject: [CRITICAL ALERT] High Risk Exploit Detected from {source_ip}

    Dear Incident Response Team,

    A High Risk security anomaly was detected by the Machine Learning Classifier:
    - Attack Type: {attack_type}
    - Sensor Node: {incident_data.get('Device', 'Generic Firewall')}
    - Source IP: {source_ip}
    - Destination IP: {dest_ip}
    - Port: {incident_data.get('Port', '80')}
    - Country: {incident_data.get('Country', 'Unknown')}
    - Risk Confidence: {pred_result.get('confidence_pct', 0.0)}%

    Automated Playbook Mitigation Triggered:
    {pred_result.get('recommendation', 'N/A')}

    The detailed case report PDF has been exported to the alerts vault:
    Path: {pdf_path}

    This message conforms to SOC-2 logging requirements.
    ========================================================================
    """
    # Write simulation to logs
    logger.warning("SMTP Mail Dispatch Simulated:")
    for line in mock_email.strip().split("\n"):
        logger.warning(line.strip())

    # 4. Generate Ticketing System JSON (ServiceNow/Jira Schema Mock)
    ticket_data = {
        "sys_id": f"TKT-{timestamp_str}-{np.random.randint(1000, 9999)}",
        "opened_by": "ML-Analytics-Engine",
        "impact": "1 - High",
        "urgency": "1 - Critical",
        "priority": "1 - Critical",
        "assignment_group": "Security Operations Center (SOC) Escalations",
        "short_description": f"Critical exploit threat '{attack_type}' from {source_ip}",
        "description": f"Incident triggered automatically by champion ML models. Playbook recommedations: Isolate {dest_ip} immediately.",
        "mitigation_playbook": pred_result.get("recommendation", "N/A"),
        "pdf_vault_path": pdf_path,
        "metadata": {
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "device": incident_data.get("Device"),
            "confidence_pct": pred_result.get("confidence_pct"),
            "failed_login_attempts": incident_data.get("Failed_Login_Count"),
            "velocity_1h": incident_data.get("Attack_Velocity")
        }
    }
    
    ticket_path = f"alerts/ticket_{timestamp_str}_{source_ip.replace('.', '_')}.json"
    with open(ticket_path, "w", encoding="utf-8") as f:
        json.dump(ticket_data, f, indent=4)
    logger.info(f"ServiceNow Incident Ticket generated at: {ticket_path}")

    return {
        "pdf_path": pdf_path,
        "email_simulated": True,
        "ticket_path": ticket_path,
        "ticket_id": ticket_data["sys_id"]
    }
