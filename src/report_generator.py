"""
Report Generator Module
Handles exporting threat analysis data to CSV and generating clean, professional
cybersecurity reports in PDF format using ReportLab.
"""

import os
import pandas as pd
from datetime import datetime

# ReportLab imports
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_csv_report(df, output_path="reports/incident_export.csv"):
    """Saves the given DataFrame as a CSV file in the reports directory."""
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"CSV report exported to {output_path}")
        return output_path
    except Exception as e:
        print(f"Failed to generate CSV report: {str(e)}")
        raise e

def _create_custom_styles():
    """Helper to register custom paragraph styles with high-contrast, security-themed colors."""
    styles = getSampleStyleSheet()
    
    # Check if they exist, else create
    try:
        styles.add(ParagraphStyle(
            name='SecurityTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            textColor=colors.HexColor('#0F172A'), # Charcoal / Navy
            spaceAfter=15,
            alignment=1 # Centered
        ))
    except ValueError:
        pass
        
    try:
        styles.add(ParagraphStyle(
            name='SecuritySubtitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            textColor=colors.HexColor('#64748B'),
            spaceAfter=25,
            alignment=1
        ))
    except ValueError:
        pass

    try:
        styles.add(ParagraphStyle(
            name='SecurityHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=12,
            spaceAfter=8,
            borderPadding=4
        ))
    except ValueError:
        pass

    try:
        styles.add(ParagraphStyle(
            name='SecurityBody',
            parent=styles['BodyText'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#334155'),
            leading=14,
            spaceAfter=8
        ))
    except ValueError:
        pass

    try:
        styles.add(ParagraphStyle(
            name='RecommendationText',
            parent=styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=10,
            textColor=colors.HexColor('#1E293B'),
            leading=14,
            leftIndent=15
        ))
    except ValueError:
        pass
        
    return styles

def generate_pdf_prediction_report(incident_data, pred_result, output_path="reports/incident_report.pdf"):
    """
    Generates a PDF analysis report for a single threat incident.
    Includes the input metadata, the ML-predicted risk level, confidence, and recommended playbooks.
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        doc = SimpleDocTemplate(output_path, pagesize=letter, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
        styles = _create_custom_styles()
        story = []
        
        # 1. Header
        story.append(Paragraph("CYBERSECURITY INCIDENT CLASSIFICATION REPORT", styles['SecurityTitle']))
        story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Incident Analytics Engine", styles['SecuritySubtitle']))
        story.append(Spacer(1, 10))
        
        # 2. Risk Level Banner
        risk_level = pred_result["predicted_risk_level"]
        conf = pred_result["confidence_pct"]
        
        # Determine background color based on risk
        if risk_level == "High Risk":
            banner_bg = colors.HexColor('#EF4444')  # Red
            banner_fg = colors.white
        elif risk_level == "Medium Risk":
            banner_bg = colors.HexColor('#F59E0B')  # Amber
            banner_fg = colors.white
        else:
            banner_bg = colors.HexColor('#10B981')  # Green
            banner_fg = colors.white

        banner_text = f"<b>CLASSIFIED THREAT LEVEL: {risk_level.upper()} ({conf}% Confidence)</b>"
        banner_data = [[Paragraph(banner_text, ParagraphStyle('BannerStyle', fontName='Helvetica-Bold', fontSize=12, textColor=banner_fg, alignment=1))]]
        
        banner_table = Table(banner_data, colWidths=[530])
        banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), banner_bg),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('BOX', (0,0), (-1,-1), 1, banner_bg),
        ]))
        
        story.append(banner_table)
        story.append(Spacer(1, 15))
        
        # 3. Incident Details Table
        story.append(Paragraph("Incident Telemetry & Parameters", styles['SecurityHeading']))
        
        details_data = [
            [Paragraph("<b>Parameter</b>", styles['SecurityBody']), Paragraph("<b>Value</b>", styles['SecurityBody'])],
            ["Source IP Address", incident_data.get('Source_IP', 'N/A')],
            ["Destination IP Address", incident_data.get('Destination_IP', 'N/A')],
            ["Attack Type", incident_data.get('Attack_Type', 'N/A')],
            ["Protocol / Port", f"{incident_data.get('Protocol', 'N/A')} / {incident_data.get('Port', 'N/A')}"],
            ["Reporting Device", incident_data.get('Device', 'N/A')],
            ["Geographic Origin (Country)", incident_data.get('Country', 'N/A')],
            ["Consecutive Failed Logins", str(incident_data.get('Failed_Login_Count', 0))],
            ["Source IP Attack Frequency", str(incident_data.get('Attack_Frequency', 1))],
            ["Suspicious IP Score (0-10)", f"{incident_data.get('Suspicious_IP_Score', 0.0):.2f}"],
        ]
        
        t = Table(details_data, colWidths=[200, 330])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#F1F5F9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(t)
        story.append(Spacer(1, 15))
        
        # 4. Probabilities Breakdown
        story.append(Paragraph("Probability Breakdown", styles['SecurityHeading']))
        prob_text = ", ".join([f"{k}: {v}%" for k, v in pred_result["all_probabilities"].items()])
        story.append(Paragraph(prob_text, styles['SecurityBody']))
        story.append(Spacer(1, 10))
        
        # 5. Playbook Recommendation
        story.append(Paragraph("Incident Response Recommended Action", styles['SecurityHeading']))
        rec_formatted = pred_result["recommendation"].replace("\n", "<br/>")
        story.append(Paragraph(rec_formatted, styles['RecommendationText']))
        
        # Build Document
        doc.build(story)
        print(f"PDF report generated successfully at: {output_path}")
        return output_path
        
    except Exception as e:
        print(f"Failed to generate PDF prediction report: {str(e)}")
        raise e

def generate_pdf_summary_report(df, output_path="reports/security_summary_report.pdf"):
    """
    Generates a summary PDF report for a collection of threat incidents.
    Includes aggregate counts, high risk alerts distribution, and a summary list of recent alerts.
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        doc = SimpleDocTemplate(output_path, pagesize=letter, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
        styles = _create_custom_styles()
        story = []
        
        # 1. Header
        story.append(Paragraph("SECURITY THREAT INCIDENT SUMMARY REPORT", styles['SecurityTitle']))
        story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Incident Analytics Framework", styles['SecuritySubtitle']))
        story.append(Spacer(1, 10))
        
        # 2. Executive Metrics Summary Table
        story.append(Paragraph("Executive Summary Metrics", styles['SecurityHeading']))
        
        total_alerts = len(df)
        high_risk_count = len(df[df['Risk_Level'] == 'High Risk'])
        med_risk_count = len(df[df['Risk_Level'] == 'Medium Risk'])
        low_risk_count = len(df[df['Risk_Level'] == 'Low Risk'])
        
        top_attacker_ip = df['Source_IP'].value_counts().index[0] if len(df) > 0 else 'N/A'
        top_attack_type = df['Attack_Type'].value_counts().index[0] if len(df) > 0 else 'N/A'
        
        metrics_data = [
            [Paragraph("<b>Metric</b>", styles['SecurityBody']), Paragraph("<b>Value</b>", styles['SecurityBody'])],
            ["Total Analyzed Incidents", str(total_alerts)],
            ["High Risk Threats (Classified)", f"{high_risk_count} ({high_risk_count/total_alerts*100:.1f}%)"],
            ["Medium Risk Threats (Classified)", f"{med_risk_count} ({med_risk_count/total_alerts*100:.1f}%)"],
            ["Low Risk Threats (Classified)", f"{low_risk_count} ({low_risk_count/total_alerts*100:.1f}%)"],
            ["Top Attacking IP Host", top_attacker_ip],
            ["Primary Attack Vector", top_attack_type],
        ]
        
        mt = Table(metrics_data, colWidths=[220, 310])
        mt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#F1F5F9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(mt)
        story.append(Spacer(1, 15))
        
        # 3. Recent Critical & High Severity Incidents
        story.append(Paragraph("Recent Threats / Incident Telemetry Log", styles['SecurityHeading']))
        story.append(Paragraph("Listing the most recent incidents recorded in this batch:", styles['SecurityBody']))
        
        # Take up to 12 most recent sorted chronologically descending
        df_sorted = df.sort_values(by='Timestamp', ascending=False).head(12)
        
        log_headers = [
            Paragraph("<b>Timestamp</b>", styles['SecurityBody']),
            Paragraph("<b>Source IP</b>", styles['SecurityBody']),
            Paragraph("<b>Attack Type</b>", styles['SecurityBody']),
            Paragraph("<b>Severity</b>", styles['SecurityBody']),
            Paragraph("<b>Risk Level</b>", styles['SecurityBody'])
        ]
        
        log_rows = [log_headers]
        for _, row in df_sorted.iterrows():
            timestamp_str = row['Timestamp'].strftime('%m-%d %H:%M') if isinstance(row['Timestamp'], datetime) else str(row['Timestamp'])[:11]
            log_rows.append([
                timestamp_str,
                row['Source_IP'],
                row['Attack_Type'],
                row['Severity'],
                row['Risk_Level']
            ])
            
        lt = Table(log_rows, colWidths=[90, 110, 120, 90, 120])
        lt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ]))
        # Note: we need text colors of headers corrected in TableStyle if they are parsed raw,
        # but since headers are Paragraphs, ParagraphStyle handles their colors. Let's make headers in table white text.
        for i in range(len(log_headers)):
            log_headers[i].style.textColor = colors.white
            
        story.append(lt)
        
        # Build Document
        doc.build(story)
        print(f"Summary PDF report generated successfully at: {output_path}")
        return output_path
        
    except Exception as e:
        print(f"Failed to generate PDF summary report: {str(e)}")
        raise e

if __name__ == "__main__":
    # Test file output locally if pandas test data is created
    import numpy as np
    try:
        from src.feature_engineering import load_cleaned_data, engineer_features
        df = engineer_features(load_cleaned_data())
        generate_pdf_summary_report(df, "reports/test_summary_report.pdf")
    except Exception as e:
        print(f"Skipping main test run: {str(e)}")
