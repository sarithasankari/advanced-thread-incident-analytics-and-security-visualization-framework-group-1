"""
Upgraded Streamlit Dashboard App
Provides interactive visualizations, live logging simulation, REST API status monitors,
ML model registries, SHAP interpretability plots, MITRE ATT&CK matrices,
time-series forecasting plots, and user administration.
"""

import os
import sys
import json
import time
import pandas as pd
import numpy as np
import streamlit as st

st.set_page_config(
    page_title="Advanced Threat Incident Analytics - SOC Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

from datetime import datetime, date

# Path configuration for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Core imports
from src.config import settings
from src.database_manager import (
    get_db, db_get_user_by_username, db_create_user, db_get_incidents, 
    db_add_incident, db_add_prediction_log, initialize_database, User, Incident, PredictionLog
)
from api.auth import verify_password, hash_password
from src.prediction import IncidentPredictor
from src.explainability import ThreatExplainer
from src.forecasting import generate_forecasts
from src.alerting_system import trigger_high_risk_alert
from src.report_generator import generate_pdf_summary_report, generate_pdf_prediction_report
from mlops.registry import ModelRegistry
from mlops.drift_detector import DriftDetector

# Visual components
from app.components import (
    plot_attack_trend_line, plot_hourly_trend_bar, plot_severity_pie, 
    plot_top_attacks_bar, plot_country_choropleth, plot_attack_protocol_heatmap,
    plot_forecasting_line, plot_shap_waterfall, plot_model_comparison_bar, THEME_COLORS
)

# Initialize database schemas
initialize_database()

# Session State Initialization
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'username' not in st.session_state:
    st.session_state['username'] = ""
if 'role' not in st.session_state:
    st.session_state['role'] = "Viewer"
if 'last_incident' not in st.session_state:
    st.session_state['last_incident'] = None
if 'last_prediction' not in st.session_state:
    st.session_state['last_prediction'] = None
if 'live_mode' not in st.session_state:
    st.session_state['live_mode'] = False

# Custom Premium Dark Glassmorphism CSS
CUSTOM_CSS = """
<style>
    /* Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');
    
    /* Global Styles */
    html, body, [class*="css"], .stApp {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
        background-color: #0B0F19 !important;
        color: #F8FAFC !important;
    }
    
    /* Body text and paragraph readability styling */
    p, span, li {
        color: #CBD5E1 !important; /* Cool gray for clean contrast */
    }
    
    /* Glassmorphic Sidebar */
    [data-testid="stSidebar"] {
        background-color: rgba(15, 23, 42, 0.96) !important;
        backdrop-filter: blur(12px) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
    }
    
    /* Header Customization */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        font-weight: 700 !important;
        letter-spacing: -0.025em !important;
        color: #F8FAFC !important;
    }
    
    /* Custom Card Component */
    .soc-card {
        background: rgba(30, 41, 59, 0.45);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 12px;
        padding: 24px;
        backdrop-filter: blur(12px);
        margin-bottom: 20px;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .soc-card:hover {
        transform: translateY(-2px);
        border-color: rgba(59, 130, 246, 0.4);
    }
    
    /* Glow effect for status alerts */
    .glow-red {
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.3) !important;
    }
    .glow-blue {
        box-shadow: 0 0 15px rgba(59, 130, 246, 0.15);
        border: 1px solid rgba(59, 130, 246, 0.3) !important;
    }
    
    /* Custom metrics container styling */
    div[data-testid="stMetric"] {
        background: rgba(30, 41, 59, 0.35) !important;
        border: 1px solid rgba(255, 255, 255, 0.06) !important;
        border-radius: 12px !important;
        padding: 18px 24px !important;
        backdrop-filter: blur(8px) !important;
        transition: all 0.3s ease;
    }
    div[data-testid="stMetric"]:hover {
        border-color: rgba(59, 130, 246, 0.3) !important;
        box-shadow: 0 4px 20px rgba(59, 130, 246, 0.08) !important;
        transform: translateY(-1px);
    }
    div[data-testid="stMetric"] label {
        color: #94A3B8 !important;
        font-size: 0.875rem !important;
        font-weight: 600 !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #F8FAFC !important;
        font-size: 1.875rem !important;
        font-weight: 800 !important;
    }
    
    /* Style all input, slider, select, and checkbox labels to be high contrast */
    label[data-testid="stWidgetLabel"] p {
        color: #E2E8F0 !important;
        font-weight: 600 !important;
    }
    div[data-testid="stSlider"] {
        color: #F1F5F9 !important;
    }
    
    /* Streamlit UI elements cleanup */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header[data-testid="stHeader"] {
        background-color: transparent !important;
    }
    header[data-testid="stHeader"] [data-testid="stHeaderActionElements"],
    header[data-testid="stHeader"] [data-testid="stConnectionStatus"] {
        display: none !important;
    }
    [data-testid="stDecoration"] {
        display: none !important;
    }
    
    /* Form container styling */
    div[data-testid="stForm"] {
        background: rgba(30, 41, 59, 0.35) !important;
        border: 1px solid rgba(255, 255, 255, 0.06) !important;
        border-radius: 16px !important;
        padding: 32px !important;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.25) !important;
        backdrop-filter: blur(12px) !important;
    }
    
    /* Selectboxes, dropdowns & inputs custom styling */
    div[data-baseweb="select"] > div {
        background-color: #1E293B !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        color: #F8FAFC !important;
    }
    input {
        background-color: #1E293B !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
    }
    
    /* Option list dropdown menus visibility */
    div[role="listbox"] {
        background-color: #1E293B !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
    }
    div[role="option"] {
        color: #E2E8F0 !important;
        background-color: transparent !important;
    }
    div[role="option"]:hover, div[role="option"][aria-selected="true"] {
        background-color: rgba(59, 130, 246, 0.2) !important;
        color: #F8FAFC !important;
    }
    
    /* Multiselect tag labels styling */
    span[data-baseweb="tag"] {
        background-color: rgba(59, 130, 246, 0.2) !important;
        border: 1px solid rgba(59, 130, 246, 0.4) !important;
        color: #60A5FA !important;
    }
    span[data-baseweb="tag"] span {
        color: #60A5FA !important;
    }
    
    /* Table & Dataframe overrides for high visibility */
    table {
        color: #E2E8F0 !important;
        background-color: rgba(30, 41, 59, 0.25) !important;
        border-collapse: collapse !important;
        border-radius: 8px !important;
        overflow: hidden !important;
    }
    th {
        background-color: rgba(59, 130, 246, 0.1) !important;
        color: #60A5FA !important;
        font-weight: 700 !important;
        border-bottom: 2px solid rgba(255, 255, 255, 0.08) !important;
        padding: 12px 16px !important;
    }
    td {
        border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
        padding: 10px 16px !important;
        color: #CBD5E1 !important;
    }
    tr:hover {
        background-color: rgba(255, 255, 255, 0.02) !important;
    }
    
    /* Buttons custom styling */
    .stButton>button, .stDownloadButton>button, .stFileUploader>button {
        background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 10px 24px !important;
        font-weight: 600 !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.25) !important;
        width: 100%;
        text-align: center !important;
    }
    .stButton>button:hover, .stDownloadButton>button:hover, .stFileUploader>button:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4) !important;
        color: white !important;
    }
    .stButton>button:active, .stDownloadButton>button:active {
        transform: translateY(1px) !important;
    }
    
    /* Sidebar glassmorphic container styling */
    section[data-testid="stSidebar"] {
        background-color: #080C14 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.04) !important;
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.3) !important;
    }

    /* Style the radio widget header label as a premium sidebar subheader */
    div[data-testid="stSidebar"] div[data-testid="stRadioButton"] > label[data-testid="stWidgetLabel"] {
        color: #64748B !important;
        font-size: 0.75rem !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
        margin-bottom: 12px !important;
        display: block !important;
    }
    
    /* Style the sidebar radio items directly */
    div[data-testid="stSidebar"] div[role="radiogroup"] label {
        background-color: rgba(15, 23, 42, 0.4) !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        margin-bottom: 8px !important;
        cursor: pointer !important;
        color: #94A3B8 !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        display: flex !important;
        align-items: center !important;
        width: 100% !important;
    }
    div[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        border-color: rgba(59, 130, 246, 0.4) !important;
        background-color: rgba(30, 41, 59, 0.5) !important;
        color: #F8FAFC !important;
        transform: translateX(4px) !important;
    }
    /* Target the selected option using multiple matching methods to guarantee execution */
    div[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked),
    div[data-testid="stSidebar"] div[role="radiogroup"] label:has(input[checked]),
    div[data-testid="stSidebar"] div[role="radiogroup"] input:checked + div,
    div[data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(139, 92, 246, 0.15) 100%) !important;
        border-color: #3B82F6 !important;
        color: #3B82F6 !important;
        font-weight: 600 !important;
        box-shadow: 0 0 15px rgba(59, 130, 246, 0.15), inset 0 0 10px rgba(59, 130, 246, 0.05) !important;
        transform: translateX(4px) !important;
    }
    /* Hide the radio button circles in the sidebar to make it look like a pure menu */
    div[data-testid="stSidebar"] div[role="radiogroup"] label div[data-testid="stMarkdownContainer"] {
        margin-left: 0px !important;
        padding-left: 0px !important;
        width: 100% !important;
        display: block !important;
    }
    div[data-testid="stSidebar"] div[role="radiogroup"] label div[data-testid="stMarkdownContainer"] p {
        margin: 0 !important;
        padding: 0 !important;
        color: inherit !important;
        font-weight: inherit !important;
    }
    /* Hide any element inside the label that is not the markdown text container */
    div[data-testid="stSidebar"] div[role="radiogroup"] label > *:not([data-testid="stMarkdownContainer"]),
    div[data-testid="stSidebar"] div[role="radiogroup"] label span[role="presentation"],
    div[data-testid="stSidebar"] div[role="radiogroup"] label div[role="presentation"],
    div[data-testid="stSidebar"] div[role="radiogroup"] label [class*="StyledRadio"] {
        display: none !important;
        width: 0px !important;
        height: 0px !important;
        opacity: 0 !important;
        visibility: hidden !important;
    }
    
    /* Sidebar collapse & expand controls premium styling */
    [data-testid="stSidebarCollapsedControl"] {
        visibility: visible !important;
        pointer-events: auto !important;
    }
    [data-testid="stSidebarCollapsedControl"] button,
    [data-testid="collapsedControl"],
    [aria-label="Expand sidebar"] {
        visibility: visible !important;
        pointer-events: auto !important;
        background-color: rgba(30, 41, 59, 0.9) !important;
        border: 1px solid rgba(59, 130, 246, 0.4) !important;
        border-radius: 50% !important;
        color: #60A5FA !important;
        box-shadow: 0 0 15px rgba(59, 130, 246, 0.3) !important;
        transition: all 0.3s ease !important;
        position: fixed !important;
        top: 12px !important;
        left: 12px !important;
        z-index: 999999 !important;
        width: 40px !important;
        height: 40px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
    }
    [data-testid="stSidebarCollapsedControl"] button:hover,
    [data-testid="collapsedControl"]:hover,
    [aria-label="Expand sidebar"]:hover {
        background-color: rgba(59, 130, 246, 0.2) !important;
        border-color: #3B82F6 !important;
        color: #F8FAFC !important;
        box-shadow: 0 0 20px rgba(59, 130, 246, 0.4) !important;
    }
    [data-testid="stSidebarCollapsedControl"] svg,
    [data-testid="collapsedControl"] svg,
    [aria-label="Expand sidebar"] svg {
        fill: #60A5FA !important;
        color: #60A5FA !important;
    }
    div[data-testid="stSidebarHeader"] button {
        color: #94A3B8 !important;
        background-color: rgba(255, 255, 255, 0.02) !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
        border-radius: 6px !important;
        transition: all 0.2s ease !important;
    }
    div[data-testid="stSidebarHeader"] button:hover {
        color: #60A5FA !important;
        border-color: rgba(59, 130, 246, 0.3) !important;
        background-color: rgba(59, 130, 246, 0.1) !important;
    }
    div[data-testid="stSidebarHeader"] button svg {
        fill: currentColor !important;
    }
    
    /* Classification banners */
    .high-risk-banner {
        padding: 16px;
        background-color: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-radius: 8px;
        color: #FCA5A5;
        font-weight: 700;
        margin-bottom: 20px;
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.1);
        text-align: center;
        letter-spacing: 0.05em;
    }
    .med-risk-banner {
        padding: 16px;
        background-color: rgba(245, 158, 11, 0.15);
        border: 1px solid rgba(245, 158, 11, 0.4);
        border-radius: 8px;
        color: #FDE047;
        font-weight: 700;
        margin-bottom: 20px;
        box-shadow: 0 0 15px rgba(245, 158, 11, 0.1);
        text-align: center;
        letter-spacing: 0.05em;
    }
    .low-risk-banner {
        padding: 16px;
        background-color: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.4);
        border-radius: 8px;
        color: #A7F3D0;
        font-weight: 700;
        margin-bottom: 20px;
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.1);
        text-align: center;
        letter-spacing: 0.05em;
    }
</style>
"""

# ==========================================
# 1. LOGIN INTERFACE (SECURE LOCK SCREEN)
# ==========================================

def render_login_screen():
    """Renders a standard security-themed login panel."""
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    st.markdown("""
        <div style="text-align: center; margin-top: 60px; margin-bottom: 30px;">
            <div style="display: inline-block; padding: 20px; background: rgba(59, 130, 246, 0.1); border-radius: 50%; border: 1px solid rgba(59, 130, 246, 0.3); box-shadow: 0 0 30px rgba(59, 130, 246, 0.2); margin-bottom: 20px;">
                <span style="font-size: 3rem;">🛡️</span>
            </div>
            <h1 style="margin: 0; font-size: 2.25rem; font-weight: 800; background: linear-gradient(135deg, #60A5FA 0%, #A78BFA 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: -0.05em;">SOC ENTERPRISE CONTROL PORTAL</h1>
            <p style="margin: 5px 0 0 0; color: #94A3B8; font-size: 0.95rem; font-weight: 500;">Secure Identity & Threat Incident Analytics Gateway</p>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 1.8, 1])
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="e.g. admin")
            password = st.text_input("Password", type="password", placeholder="••••••••")
            submit = st.form_submit_button("Access SOC Control Center")
            
            if submit:
                with get_db() as db:
                    user = db_get_user_by_username(db, username)
                    if user and verify_password(password, user.password_hash):
                        st.session_state['authenticated'] = True
                        st.session_state['username'] = user.username
                        st.session_state['role'] = user.role
                        st.success("Access Granted. Redirecting to SOC Control Panel...")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Access Denied: Incorrect username or password credentials.")

# ==========================================
# 2. APPLICATION ENTRYPOINT
# ==========================================

def main():
    # Render lock screen if not logged in
    if not st.session_state['authenticated']:
        render_login_screen()
        return

    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    # Sidebar Header (Premium User Avatar Profile Card)
    st.sidebar.markdown(f"""
        <div style="text-align: center; padding: 24px 16px; background: rgba(30, 41, 59, 0.25); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 12px; margin-bottom: 24px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2); backdrop-filter: blur(12px);">
            <div style="width: 50px; height: 50px; border-radius: 50%; background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 100%); display: flex; align-items: center; justify-content: center; margin: 0 auto 12px auto; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); position: relative;">
                <span style="font-size: 1.4rem; color: white;">👤</span>
                <span style="position: absolute; bottom: 0; right: 0; width: 12px; height: 12px; border-radius: 50%; background-color: #10B981; border: 2px solid #080C14; box-shadow: 0 0 8px #10B981;"></span>
            </div>
            <h3 style="margin: 0; font-size: 1.15rem; color: #F8FAFC; font-weight: 700; letter-spacing: -0.01em;">{st.session_state['username']}</h3>
            <span style="display: inline-block; background-color: rgba(59, 130, 246, 0.1); color: #60A5FA; padding: 3px 10px; border-radius: 6px; font-size: 9px; font-weight: 700; border: 1px solid rgba(59, 130, 246, 0.25); margin-top: 8px; text-transform: uppercase; letter-spacing: 0.05em;">
                {st.session_state['role']}
            </span>
        </div>
    """, unsafe_allow_html=True)

    # Navigation menu (RBAC filtered via Option Menu)
    from streamlit_option_menu import option_menu
    
    menu_options = ["📊 SOC Overview Dashboard", "🔍 Security Logs Explorer", "🔮 Threat Prediction portal", "🛡️ SHAP Explainability Portal", "🕸️ MITRE ATT&CK & CVSS Mapping", "📈 ML Performance Analytics", "🔮 Time-Series Forecasting"]
    
    # Restrict administrative panels
    if st.session_state['role'] in ["Admin", "Security Analyst"]:
        menu_options.append("🤖 MLOps Drift & Registry")
    if st.session_state['role'] == "Admin":
        menu_options.append("👤 User Management")

    with st.sidebar:
        selected_option = option_menu(
            menu_title="Navigation",
            options=menu_options,
            icons=None,
            menu_icon=None,
            default_index=0,
            key="nav_menu",
            styles={
                "container": {"padding": "0px", "background-color": "transparent"},
                "nav-link": {
                    "font-size": "12px", 
                    "text-align": "left", 
                    "margin": "4px 0px", 
                    "color": "#94A3B8",
                    "padding": "8px 12px",
                    "border-radius": "8px",
                    "transition": "all 0.2s ease",
                    "--hover-color": "rgba(30, 41, 59, 0.4)"
                },
                "nav-link-selected": {
                    "background": "linear-gradient(135deg, rgba(59, 130, 246, 0.12) 0%, rgba(139, 92, 246, 0.12) 100%)", 
                    "border": "1px solid rgba(59, 130, 246, 0.35)", 
                    "color": "#3B82F6", 
                    "font-weight": "600",
                    "box-shadow": "0 0 15px rgba(59, 130, 246, 0.15)"
                },
                "menu-title": {
                    "color": "#64748B", 
                    "font-size": "10px", 
                    "text-transform": "uppercase", 
                    "letter-spacing": "0.08em", 
                    "font-weight": "700", 
                    "padding-left": "8px",
                    "margin-bottom": "8px"
                }
            }
        )
        
    page = selected_option if selected_option else "📊 SOC Overview Dashboard"
    
    st.sidebar.write("---")
    if st.sidebar.button("Logout of Platform"):
        st.session_state['authenticated'] = False
        st.session_state['username'] = ""
        st.session_state['role'] = "Viewer"
        st.rerun()

    # Load dataset for display
    processed_path = "data/processed/cyber_incidents_processed.csv"
    if not os.path.exists(processed_path):
        st.error("Ingested/Feature Engineered dataset missing. Please run generation and engineering modules.")
        return
        
    df = pd.read_csv(processed_path)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])

    # Custom Premium Top Header
    st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: rgba(30, 41, 59, 0.35); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 12px; margin-bottom: 28px; backdrop-filter: blur(12px);">
            <div>
                <h1 style="margin: 0; font-size: 1.85rem; background: linear-gradient(135deg, #60A5FA 0%, #A78BFA 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 800; letter-spacing: -0.03em;">🛡️ SOC INCIDENT ANALYTICS CONTROL CENTER</h1>
                <p style="margin: 4px 0 0 0; font-size: 0.85rem; color: #94A3B8; font-weight: 500;">Real-time Telemetry, ML Threat Intelligence & Automated Playbooks</p>
            </div>
            <div style="text-align: right;">
                <span style="font-size: 0.75rem; background-color: rgba(16, 185, 129, 0.15); color: #34D399; padding: 4px 10px; border-radius: 9999px; font-weight: 700; border: 1px solid rgba(16, 185, 129, 0.3); letter-spacing: 0.05em;">
                    ● SYSTEM SECURE
                </span>
                <p style="margin: 6px 0 0 0; font-size: 0.75rem; color: #64748B; font-weight: 600;">System Version 2.4.0</p>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # ==========================================
    # VIEW 1: SOC OVERVIEW DASHBOARD
    # ==========================================
    if page == "📊 SOC Overview Dashboard":
        st.subheader("SOC Incident Telemetry Overview")
        
        # Live Monitoring Switch
        live_chk = st.checkbox("🔄 Enable Live Data Feed Simulation (Auto Refresh)")
        if live_chk:
            st.session_state['live_mode'] = True
            # Simulate streaming logs into database
            with get_db() as db:
                mock_row = {
                    "timestamp": datetime.now(),
                    "source_ip": f"194.26.29.{np.random.randint(10, 250)}",
                    "destination_ip": "10.100.1.25",
                    "attack_type": np.random.choice(["SQL Injection", "Brute Force", "Port Scanning", "DDoS"]),
                    "protocol": np.random.choice(["TCP", "UDP"]),
                    "port": int(np.random.choice([80, 443, 22, 3306])),
                    "severity": np.random.choice(["Medium", "High", "Critical"]),
                    "status": "Detected",
                    "country": np.random.choice(["RU", "CN", "US", "DE"]),
                    "device": "WAF",
                    "action_taken": "Alerted",
                    "failed_login_count": int(np.random.choice([0, 2, 5])),
                    "session_duration": float(np.random.uniform(5.0, 120.0))
                }
                db_add_incident(db, mock_row)
            
            time.sleep(3) # trigger refresh loop every 3 seconds
            st.rerun()
            
        # Standard KPI row
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f"""
                <div style="background: rgba(30, 41, 59, 0.3); border: 1px solid rgba(255, 255, 255, 0.04); border-radius: 12px; padding: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15); backdrop-filter: blur(12px); display: flex; align-items: center; gap: 16px; min-height: 110px;">
                    <div style="font-size: 1.5rem; color: #60A5FA; background: rgba(96, 165, 250, 0.1); border-radius: 10px; width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; border: 1px solid rgba(96, 165, 250, 0.2);">📊</div>
                    <div>
                        <p style="margin: 0; color: #64748B; font-size: 0.7rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em;">Total Alerts</p>
                        <h3 style="margin: 2px 0 0 0; color: #F8FAFC; font-size: 1.45rem; font-weight: 800; letter-spacing: -0.02em;">{len(df):,}</h3>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
        with col2:
            high_count = len(df[df['Risk_Level'] == 'High Risk'])
            high_pct = (high_count / len(df) * 100) if len(df) > 0 else 0
            st.markdown(f"""
                <div style="background: rgba(30, 41, 59, 0.3); border: 1px solid rgba(255, 255, 255, 0.04); border-radius: 12px; padding: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15); backdrop-filter: blur(12px); display: flex; align-items: center; gap: 16px; min-height: 110px;">
                    <div style="font-size: 1.5rem; color: #F87171; background: rgba(248, 113, 113, 0.1); border-radius: 10px; width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; border: 1px solid rgba(248, 113, 113, 0.2);">🚨</div>
                    <div>
                        <p style="margin: 0; color: #64748B; font-size: 0.7rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em;">High Risk</p>
                        <h3 style="margin: 2px 0 0 0; color: #F8FAFC; font-size: 1.45rem; font-weight: 800; letter-spacing: -0.02em;">{high_count:,}</h3>
                        <span style="font-size: 0.65rem; color: #F87171; font-weight: 600;">{high_pct:.1f}% total</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
        with col3:
            blocked_count = df['Action_Taken'].isin(['Blocked', 'Isolated']).sum()
            block_rate = (blocked_count / len(df) * 100) if len(df) > 0 else 0
            st.markdown(f"""
                <div style="background: rgba(30, 41, 59, 0.3); border: 1px solid rgba(255, 255, 255, 0.04); border-radius: 12px; padding: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15); backdrop-filter: blur(12px); display: flex; align-items: center; gap: 16px; min-height: 110px;">
                    <div style="font-size: 1.5rem; color: #34D399; background: rgba(52, 211, 153, 0.1); border-radius: 10px; width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; border: 1px solid rgba(52, 211, 153, 0.2);">🛡️</div>
                    <div>
                        <p style="margin: 0; color: #64748B; font-size: 0.7rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em;">Block Rate</p>
                        <h3 style="margin: 2px 0 0 0; color: #F8FAFC; font-size: 1.45rem; font-weight: 800; letter-spacing: -0.02em;">{block_rate:.1f}%</h3>
                        <span style="font-size: 0.65rem; color: #34D399; font-weight: 600;">{blocked_count:,} blocked</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
        with col4:
            top_country = df['Country'].value_counts().index[0] if not df.empty else "N/A"
            st.markdown(f"""
                <div style="background: rgba(30, 41, 59, 0.3); border: 1px solid rgba(255, 255, 255, 0.04); border-radius: 12px; padding: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15); backdrop-filter: blur(12px); display: flex; align-items: center; gap: 16px; min-height: 110px;">
                    <div style="font-size: 1.5rem; color: #A78BFA; background: rgba(167, 139, 250, 0.1); border-radius: 10px; width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; border: 1px solid rgba(167, 139, 250, 0.2);">🌐</div>
                    <div>
                        <p style="margin: 0; color: #64748B; font-size: 0.7rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.08em;">Top Origin</p>
                        <h3 style="margin: 2px 0 0 0; color: #F8FAFC; font-size: 1.45rem; font-weight: 800; letter-spacing: -0.02em;">{top_country}</h3>
                        <span style="font-size: 0.65rem; color: #A78BFA; font-weight: 600;">Primary Threat</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        # Plotly rows
        st.write(" ")
        tcol1, tcol2 = st.columns([2, 1])
        with tcol1:
            st.plotly_chart(plot_attack_trend_line(df), use_container_width=True)
        with tcol2:
            st.plotly_chart(plot_severity_pie(df), use_container_width=True)
            
        mcol1, mcol2 = st.columns(2)
        with mcol1:
            st.plotly_chart(plot_top_attacks_bar(df), use_container_width=True)
        with mcol2:
            st.plotly_chart(plot_country_choropleth(df), use_container_width=True)

    # ==========================================
    # VIEW 2: SECURITY LOGS EXPLORER
    # ==========================================
    elif page == "🔍 Security Logs Explorer":
        st.subheader("Security Ingestion Logs Explorer")
        
        # Sidebar Filters
        st.sidebar.markdown("### Filters")
        selected_attack = st.sidebar.multiselect("Attack Types", df['Attack_Type'].unique().tolist(), default=df['Attack_Type'].unique().tolist())
        selected_severity = st.sidebar.multiselect("Severities", df['Severity'].unique().tolist(), default=df['Severity'].unique().tolist())
        
        # Filter dataframe
        filtered_df = df[df['Attack_Type'].isin(selected_attack) & df['Severity'].isin(selected_severity)]
        
        st.write(f"Displaying **{len(filtered_df):,}** logs matching selection:")
        st.dataframe(filtered_df.sort_values(by='Timestamp', ascending=False).head(500), use_container_width=True)
        
        # Exporter
        csv_logs = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Filtered Logs to CSV",
            data=csv_logs,
            file_name="soc_filtered_logs.csv",
            mime="text/csv"
        )

    # ==========================================
    # VIEW 3: THREAT PREDICTION & EXPLAINER PORTAL
    # ==========================================
    elif page == "🔮 Threat Prediction portal":
        st.subheader("Real-Time Incident Classifier Playbook")
        st.write("Provide telemetry credentials to calculate threat levels, explain prediction drivers via SHAP, and create ServiceNow tickets.")
        
        # Fetch model
        try:
            ml_predictor = IncidentPredictor(model_path=settings.MODEL_PATH)
            ml_explainer = ThreatExplainer(pipeline=ml_predictor.pipeline)
        except Exception as e:
            st.warning(f"ML Pipeline is uninitialized. Train models first. Error: {str(e)}")
            return
            
        with st.form("incident_prediction_form"):
            st.markdown("### Telemetry Inputs")
            c1, c2 = st.columns(2)
            with c1:
                attack_type = st.selectbox("Attack Category", ["DDoS", "SQL Injection", "Brute Force", "Phishing", "Malware", "Port Scanning"])
                protocol = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"])
                port = st.number_input("Destination Port", min_value=0, max_value=65535, value=80)
                device = st.selectbox("Appliance Sensor", ["Firewall", "IDS/IPS", "WAF", "Endpoint agent"])
                country = st.selectbox("Origin Country", ["US", "CN", "RU", "DE", "GB", "IN", "JP", "BR", "CA", "FR"])
                user_role = st.selectbox("User Organizational Role", ["Standard Employee", "Admin", "Developer", "DB Admin", "HR Specialist"])
            with c2:
                failed_logins = st.slider("Failed Logins Count", 0, 20, 0)
                session_duration = st.number_input("Session Duration (seconds)", min_value=0.0, value=30.0)
                auth_method = st.selectbox("Authentication Method", ["Password", "MFA", "SSH Key", "API Key", "JWT"])
                
                # Mock historical reputation metrics
                ip_frequency = st.number_input("Attacker IP Frequency Count", min_value=1, value=1)
                suspicious_score = st.slider("Reputation Score (0-10)", 0.0, 10.0, 0.0)
                
            submit_pred = st.form_submit_button("Execute ML Prediction")
            
        if submit_pred:
            # Reconstruct variables for model inputs
            dt_now = datetime.now()
            incident_data = {
                "Attack_Type": attack_type,
                "Protocol": protocol,
                "Port": port,
                "Device": device,
                "Country": country,
                "Failed_Login_Count": failed_logins,
                "Hour": dt_now.hour,
                "Weekend_Flag": 1 if dt_now.weekday() >= 5 else 0,
                "Attack_Frequency": ip_frequency,
                "Suspicious_IP_Score": suspicious_score,
                "Session_Duration": session_duration,
                "User_Role": user_role,
                "Auth_Method": auth_method,
                "Source_IP": f"194.26.29.{np.random.randint(10, 250)}",
                "Destination_IP": "10.100.1.25"
            }
            
            # Predict
            res = ml_predictor.predict_incident(incident_data)
            
            # Store in session state for SHAP tab
            st.session_state['last_incident'] = incident_data
            st.session_state['last_prediction'] = res
            
            risk = res["predicted_risk_level"]
            conf = res["confidence_pct"]
            
            # High severity triggers
            alert_res = None
            if risk == "High Risk":
                st.markdown(f'<div class="high-risk-banner">CRITICAL CLASSIFICATION: {risk.upper()} (Confidence: {conf}%)</div>', unsafe_allow_html=True)
                with get_db() as db:
                    alert_res = trigger_high_risk_alert(incident_data, res, db=db)
                st.success(f"🚨 ServiceNow Escalation Ticket Created: **{alert_res['ticket_id']}**")
            elif risk == "Medium Risk":
                st.markdown(f'<div class="med-risk-banner">WARNING CLASSIFICATION: {risk.upper()} (Confidence: {conf}%)</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="low-risk-banner">INFORMATIONAL CLASSIFICATION: {risk.upper()} (Confidence: {conf}%)</div>', unsafe_allow_html=True)

            rcol1, rcol2 = st.columns(2)
            with rcol1:
                st.markdown("### Playbook Response Action")
                st.write(res["recommendation"])
            with rcol2:
                # Plot probabilities
                probs = res["all_probabilities"]
                fig_probs = px.bar(
                    x=list(probs.values()), y=list(probs.keys()),
                    orientation='h',
                    labels={'x': 'Probability (%)', 'y': 'Class'},
                    color=list(probs.keys()),
                    color_discrete_map={
                        "High Risk": THEME_COLORS["High Risk"],
                        "Medium Risk": THEME_COLORS["Medium Risk"],
                        "Low Risk": THEME_COLORS["Low Risk"]
                    },
                    range_x=[0, 100]
                )
                fig_probs.update_layout(template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', margin=dict(l=10,r=10,t=10,b=10))
                st.plotly_chart(fig_probs, use_container_width=True)

    # ==========================================
    # VIEW 4: SHAP EXPLAINABILITY PORTAL
    # ==========================================
    elif page == "🛡️ SHAP Explainability Portal":
        st.subheader("Model Interpretability (Explainable AI)")
        st.write("Understand which security metrics most influenced the machine learning classifier decisions.")
        
        if st.session_state['last_incident'] is None:
            # Auto-load the latest threat log trace from the database if session is empty
            with get_db() as db:
                latest_incidents = db_get_incidents(db, limit=1)
            if latest_incidents:
                inc = latest_incidents[0]
                st.session_state['last_incident'] = {
                    "Attack_Type": inc.attack_type,
                    "Protocol": inc.protocol,
                    "Port": inc.port,
                    "Device": inc.device,
                    "Country": inc.country,
                    "Failed_Login_Count": inc.failed_login_count,
                    "Hour": inc.timestamp.hour if inc.timestamp else 12,
                    "Weekend_Flag": 1 if inc.timestamp and inc.timestamp.weekday() >= 5 else 0,
                    "Attack_Frequency": 1,
                    "Suspicious_IP_Score": 1.0,
                    "Session_Duration": inc.session_duration,
                    "User_Role": "Standard Employee",
                    "Auth_Method": "Password",
                    "Source_IP": inc.source_ip,
                    "Destination_IP": inc.destination_ip
                }
                try:
                    ml_predictor = IncidentPredictor(model_path=settings.MODEL_PATH)
                    st.session_state['last_prediction'] = ml_predictor.predict_incident(st.session_state['last_incident'])
                except Exception:
                    pass

        if st.session_state['last_incident'] is None:
            st.info("No prediction traces loaded in session. Please execute a threat prediction form call first.")
            return
            
        try:
            ml_predictor = IncidentPredictor(model_path=settings.MODEL_PATH)
            ml_explainer = ThreatExplainer(pipeline=ml_predictor.pipeline)
        except Exception as e:
            st.error(f"Failed to load SHAP explainer objects: {str(e)}")
            return
            
        incident_df = pd.DataFrame([st.session_state['last_incident']])
        risk_labels = {0: "Low Risk", 1: "Medium Risk", 2: "High Risk"}
        inverse_labels = {v: k for k, v in risk_labels.items()}
        pred_idx = inverse_labels.get(st.session_state['last_prediction']["predicted_risk_level"], 0)
        
        with st.spinner("Calculating SHAP values..."):
            shap_res = ml_explainer.explain_instance(incident_df, pred_idx)
            
        if shap_res["success"]:
            # Plot attributions
            st.plotly_chart(plot_shap_waterfall(shap_res["feature_impacts"]), use_container_width=True)
            
            # Print plain English descriptions
            st.markdown("### Top Security Decision Drivers")
            for explanation in shap_res["explanations"]:
                st.markdown(f"- {explanation}")
        else:
            st.warning("SHAP Attributions fallback active. Displaying default heuristic playbook logs:")
            for explanation in shap_res["explanations"]:
                st.markdown(f"- {explanation}")

    # ==========================================
    # VIEW 5: TIME-SERIES FORECASTING
    # ==========================================
    elif page == "🔮 Time-Series Forecasting":
        st.subheader("Future Alert Volume Forecasting")
        st.write("ARIMA predictions indicating upcoming attack peaks for capacity planning.")
        
        with st.spinner("Calculating time-series trends..."):
            forecast_df, aggregates = generate_forecasts()
            
        st.plotly_chart(plot_forecasting_line(forecast_df, df), use_container_width=True)
        
        st.markdown("### Forecast Aggregates Summary")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Weekly Estimated Alerts Count", f"{aggregates['weekly']['forecast']:.0f}", delta=f"{aggregates['weekly']['lower_bound']:.0f} to {aggregates['weekly']['upper_bound']:.0f} (95% CI)")
        with col2:
            st.metric("Monthly Estimated Alerts Count", f"{aggregates['monthly']['forecast']:.0f}", delta=f"{aggregates['monthly']['lower_bound']:.0f} to {aggregates['monthly']['upper_bound']:.0f} (95% CI)")

    # ==========================================
    # VIEW 6: MITRE ATT&CK & CVSS MAPPING
    # ==========================================
    elif page == "🕸️ MITRE ATT&CK & CVSS Mapping":
        st.subheader("Security Intelligence Mappings")
        st.write("Align threat alerts to institutional security frameworks (MITRE ATT&CK, OWASP, and CVSS).")
        
        mappings = [
            {"Attack Type": "DDoS", "MITRE Tactic": "Impact", "MITRE Technique": "T1498 - Network Denial of Service", "OWASP Category": "N/A", "CVSS Score": "8.6 (High)", "Controls": "Ingress Rate Limiting, CDN Scrubbing"},
            {"Attack Type": "SQL Injection", "MITRE Tactic": "Initial Access", "MITRE Technique": "T1190 - Exploit Public Application", "OWASP Category": "A03:2021-Injection", "CVSS Score": "9.8 (Critical)", "Controls": "Parameterized queries, WAF filters"},
            {"Attack Type": "Brute Force", "MITRE Tactic": "Credential Access", "MITRE Technique": "T1110 - Brute Force", "OWASP Category": "A07:2021-Identification Failure", "CVSS Score": "7.5 (High)", "Controls": "MFA, Lockout Thresholds"},
            {"Attack Type": "Phishing", "MITRE Tactic": "Initial Access", "MITRE Technique": "T1566 - Phishing", "OWASP Category": "N/A", "CVSS Score": "6.5 (Medium)", "Controls": "SPF/DKIM filters, Employee Training"},
            {"Attack Type": "Malware", "MITRE Tactic": "Execution", "MITRE Technique": "T1204 - User Execution", "OWASP Category": "N/A", "CVSS Score": "8.8 (High)", "Controls": "EDR isolation, Application Whitelisting"},
            {"Attack Type": "Port Scanning", "MITRE Tactic": "Reconnaissance", "MITRE Technique": "T1046 - Active Scanning", "OWASP Category": "N/A", "CVSS Score": "5.3 (Medium)", "Controls": "Port blockings, IP reputation drops"}
        ]
        st.table(pd.DataFrame(mappings))

    # ==========================================
    # VIEW 7: ML PERFORMANCE ANALYTICS
    # ==========================================
    elif page == "📈 ML Performance Analytics":
        st.subheader("Machine Learning Performance Diagnostics")
        
        metrics_path = settings.METRICS_PATH
        if not os.path.exists(metrics_path):
            st.warning("Model metrics data missing. Please train ML pipelines first.")
            return
            
        with open(metrics_path, "r") as f:
            metrics = json.load(f)
            
        st.success(f"Champion Pipeline: **{metrics['best_model_name']}**")
        
        # Plot model comparative bars
        st.plotly_chart(plot_model_comparison_bar(metrics["metrics"]), use_container_width=True)
        
        # Display confusion matrix of champion
        best_name = metrics['best_model_name']
        # Clean naming for files
        clean_name = best_name.replace("Registry Version ", "") if "Registry Version" in best_name else best_name
        clean_name = clean_name.replace("Version ", "") if "Version" in clean_name else clean_name
        cm_file = f"{clean_name.lower().replace(' ', '_')}_cm.png"
        cm_path = os.path.join("models", cm_file)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### Champion Confusion Matrix")
            if os.path.exists(cm_path):
                st.image(cm_path, caption=f"Confusion Matrix: {best_name}", width=400)
            else:
                st.info("Confusion Matrix image missing.")
        with col2:
            st.markdown("### Feature Importance Ranking")
            fi_path = "models/feature_importance.png"
            if os.path.exists(fi_path):
                st.image(fi_path, caption="Feature Importances", width=420)
            else:
                st.info("Feature importance plot missing.")

    # ==========================================
    # VIEW 8: MLOPS DRIFT & REGISTRY
    # ==========================================
    elif page == "🤖 MLOps Drift & Registry":
        st.subheader("MLOps Platform Controls")
        
        # 1. Model Registry
        st.markdown("### Model Version Registry")
        reg = ModelRegistry()
        models = reg.list_models()
        
        if not models:
            st.info("No registered model versions found.")
        else:
            reg_rows = []
            for m in models:
                m_metrics = m.get("metrics", {})
                if isinstance(m_metrics, dict) and "metrics" in m_metrics:
                    model_metrics_dict = m_metrics["metrics"]
                else:
                    model_metrics_dict = m_metrics
                
                rf_f1 = f"{model_metrics_dict.get('Random Forest', {}).get('f1_score', 0.0)*100:.2f}%" if isinstance(model_metrics_dict, dict) and 'Random Forest' in model_metrics_dict else "N/A"
                xgb_f1 = f"{model_metrics_dict.get('XGBoost', {}).get('f1_score', 0.0)*100:.2f}%" if isinstance(model_metrics_dict, dict) and 'XGBoost' in model_metrics_dict else "N/A"
                gb_f1 = f"{model_metrics_dict.get('Gradient Boosting', {}).get('f1_score', 0.0)*100:.2f}%" if isinstance(model_metrics_dict, dict) and 'Gradient Boosting' in model_metrics_dict else "N/A"
                
                reg_rows.append({
                    "Version": m.get("version", "Unknown"),
                    "Registered At": m.get("registered_at", "Unknown"),
                    "Random Forest F1": rf_f1,
                    "XGBoost F1": xgb_f1,
                    "Gradient Boosting F1": gb_f1,
                })
            reg_df = pd.DataFrame(reg_rows)
            st.dataframe(reg_df, use_container_width=True)
            
            # Promotion Form
            st.markdown("#### Promote Version to Champion")
            versions = [m["version"] for m in models]
            promote_ver = st.selectbox("Select Version to Promote", versions)
            if st.button("Promote to Active Production Champion"):
                reg.promote_to_champion(promote_ver)
                st.success(f"Model version '{promote_ver}' successfully promoted to champion model!")
                st.rerun()

        # 2. Data Drift Detection
        st.write(" ")
        st.markdown("### Real-Time Data Drift Analysis")
        st.write("Performs Population Stability Index (PSI) drift monitoring on current incoming alerts.")
        
        # Load drift detector
        detector = DriftDetector()
        
        # Compare historical data (first 5,000 rows as expected) against latest database incidents
        with get_db() as db:
            incidents = db_get_incidents(db, limit=5000)
        
        if len(incidents) < 10:
            st.info("Insufficient database entries to compute drift. Feed more telemetry logs.")
            return
            
        inc_df = pd.DataFrame([item.to_dict() for item in incidents])
        inc_df['Timestamp'] = pd.to_datetime(inc_df['Timestamp'])
        
        # Align headers to lowercase mapping
        expected_df = df.copy()
        
        features_to_check = ['Failed_Login_Count', 'Session_Duration', 'Port']
        
        # Compute drift
        report = detector.analyze_dataset_drift(expected_df, inc_df, features_to_check)
        
        st.metric("System Mean Drift Index (PSI)", f"{report['mean_psi']:.4f}", delta="Drift Detected" if report['retrain_suggested'] else "Stable")
        
        st.markdown("#### Feature PSI Breakdown")
        st.table(pd.DataFrame([
            {"Feature": k, "PSI Score": v, "Status": "🚨 drifted" if v >= 0.25 else ("⚠️ moderate shift" if v >= 0.1 else "✅ stable")}
            for k, v in report["feature_psi_scores"].items()
        ]))

    # ==========================================
    # VIEW 9: USER MANAGEMENT (ADMIN ONLY)
    # ==========================================
    elif page == "👤 User Management":
        st.subheader("SOC Identity Management")
        
        st.markdown("### Active Security Users")
        with get_db() as db:
            users = db.query(User).all()
            
        users_df = pd.DataFrame([u.to_dict() for u in users])
        st.table(users_df)
        
        st.write(" ")
        st.markdown("### Create New User Credentials")
        with st.form("create_user_form"):
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            new_role = st.selectbox("Role Assignment", ["Viewer", "Security Analyst", "Admin"])
            submit_user = st.form_submit_button("Register User")
            
            if submit_user:
                if len(new_user) < 3 or len(new_pass) < 6:
                    st.error("Username must be >= 3 characters. Password must be >= 6 characters.")
                else:
                    with get_db() as db:
                        existing = db_get_user_by_username(db, new_user)
                        if existing:
                            st.error(f"User '{new_user}' already exists.")
                        else:
                            db_create_user(db, new_user, hash_password(new_pass), new_role)
                            st.success(f"User '{new_user}' successfully registered with role '{new_role}'!")
                            time.sleep(1)
                            st.rerun()
if __name__ == "__main__":
    main()
