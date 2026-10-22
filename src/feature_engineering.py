"""
Advanced Feature Engineering Module
Calculates 14 high-value cybersecurity indicators and normalizes threat risk scores.
Provides mathematical and technical explanations for each engineered feature.
"""

import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import numpy as np
from datetime import datetime
from src.utils.logger import get_logger

logger = get_logger("feature_engineering")

def load_cleaned_data(file_path: str = "data/processed/cyber_incidents_cleaned.csv") -> pd.DataFrame:
    """Loads the preprocessed cleaned dataset. If missing, automatically runs preprocessing."""
    if not os.path.exists(file_path):
        logger.warning(f"Cleaned dataset not found at '{file_path}'. Automatically invoking preprocessing pipeline...")
        from src.preprocessing import run_preprocessing_pipeline
        return run_preprocessing_pipeline(cleaned_path=file_path)
    logger.info(f"Loading cleaned dataset from: {file_path}")
    return pd.read_csv(file_path)

def calculate_advanced_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Computes 14 advanced security intelligence features:
    
    1. Attack Velocity: Rolling 1-hour count of alerts per Source IP.
       - Math: Count(event) for IP in [t - 1h, t].
       - Utility: Identifies automation and script-based scanning/brute forcing.
       
    2. Threat Density: Ratio of high/critical alerts to total alerts per Source IP.
       - Math: CumSum(High/Critical Severity) / CumSum(Total Events).
       - Utility: Isolates high-intensity targeted threats from background scan noise.
       
    3. IP Reputation Score: Weighted cumulative index of past event severities and actions.
       - Math: CumSum(Severity_Weight * Action_Weight).
       - Utility: Assesses the historical threat profile of the attacker host.
       
    4. Historical Threat Count: Lifetime incident count for the Source IP.
       - Math: Cumulative chronological occurrence count.
       - Utility: Tracks persistent threats and advanced persistent threat (APT) actors.
       
    5. Rolling Incident Average: 7-day daily incident average for the entire infrastructure.
       - Math: 7-day rolling mean of daily aggregate counts.
       - Utility: Contextualizes system-wide alert spikes against historical baselines.
       
    6. Failed Login Frequency: Sum of failed authentication attempts in the last 15 minutes.
       - Math: Sum(Failed_Login_Count) for IP in [t - 15min, t].
       - Utility: Strong indicator of horizontal or vertical brute force campaigns.
       
    7. Session Duration Anomaly: Z-score of session duration segmented by Attack Type.
       - Math: (Duration - Mean_Type) / Std_Type.
       - Utility: Flags data exfiltration (abnormally long) or scan probes (abnormally short).
       
    8. Geographic Anomaly Score: Inverted country occurrence frequency.
       - Math: 1.0 - (Country_Count / Total_Count).
       - Utility: Highlights impossible travel or connection origins from unexpected locations.
       
    9. User Behaviour Anomaly Score: Compound weight of roles, login methods, and authentication failures.
       - Math: Failed_Login_Count * Role_Weight * Auth_Method_Weight.
       - Utility: Detects credential stuffing and privilege escalation attempts.
       
    10. Login Time Anomaly: Flag indicating activity outside business hours or on weekends.
        - Math: 1 if Hour < 8 or Hour > 18 or Weekend_Flag == 1 else 0.
        - Utility: Targets out-of-hours breaches when defense teams may be offline.
        
    11. Attack Burst Detection: Rolling standard deviation threshold of 10-minute bins.
        - Math: 1 if bin_count > (mean_bin + 1.5 * std_bin) else 0.
        - Utility: Detects burst attacks like sudden DDoS surges or rapid vulnerability scans.
        
    12. Threat Score Normalization: Scaling composite risk scores onto a standard 0-100 range.
        - Math: ((Risk - Min) / (Max - Min)) * 100.
        - Utility: Visual compliance standardization for dashboards and ticketing.
        
    13. Device Risk Score: Mean risk score of historical events processed by each security device type.
        - Math: Mean(Risk_Score) grouped by Device.
        - Utility: Measures sensor efficacy and localized risk density.
        
    14. Country Risk Score: Mean risk score of historical events originating from each country.
        - Math: Mean(Risk_Score) grouped by Country.
        - Utility: Adds geographic weights to incoming threat evaluations.
    """
    logger.info("Initializing Advanced Feature Engineering pipeline...")
    fe_df = df.copy()

    # Ensure chronological sorting
    fe_df['Timestamp'] = pd.to_datetime(fe_df['Timestamp'])
    fe_df = fe_df.sort_values(by='Timestamp').reset_index(drop=True)
    fe_df['incident_id'] = fe_df.index
    
    # ----------------------------------------------------
    # 1. Attack Velocity & 6. Failed Login Frequency (Rolling Windows)
    # ----------------------------------------------------
    logger.info("Calculating rolling windows (Attack Velocity, Failed Login Frequency)...")
    # Temporarily index by Timestamp to perform datetime rolling operations
    temp_df = fe_df.set_index('Timestamp')
    
    # Attack Velocity (1-hour window per Source_IP)
    velocity = temp_df.groupby('Source_IP')['incident_id'].rolling('1h').count().reset_index()
    velocity = velocity.rename(columns={'incident_id': 'Attack_Velocity'})
    
    # Failed Login Frequency (15-minute window per Source_IP)
    login_freq = temp_df.groupby('Source_IP')['Failed_Login_Count'].rolling('15min').sum().reset_index()
    login_freq = login_freq.rename(columns={'Failed_Login_Count': 'Failed_Login_Frequency'})
    
    # Merge rolling calculations back
    fe_df = pd.merge(fe_df, velocity, on=['Source_IP', 'Timestamp'], how='left')
    fe_df = pd.merge(fe_df, login_freq, on=['Source_IP', 'Timestamp'], how='left')
    
    # Fill NAs in case of merge alignment gaps
    fe_df['Attack_Velocity'] = fe_df['Attack_Velocity'].fillna(1).astype(int)
    fe_df['Failed_Login_Frequency'] = fe_df['Failed_Login_Frequency'].fillna(0).astype(int)

    # ----------------------------------------------------
    # 4. Historical Threat Count (Attack_Frequency)
    # ----------------------------------------------------
    logger.info("Calculating cumulative counts (Historical Threat Count)...")
    fe_df['Historical_Threat_Count'] = fe_df.groupby('Source_IP').cumcount() + 1
    
    # ----------------------------------------------------
    # 2. Threat Density
    # ----------------------------------------------------
    logger.info("Calculating Threat Density...")
    high_sev_mask = fe_df['Severity'].isin(['High', 'Critical']).astype(int)
    fe_df['Cumulative_High_Sev'] = fe_df.groupby('Source_IP')['Severity'].transform(
        lambda x: x.isin(['High', 'Critical']).cumsum()
    )
    fe_df['Threat_Density'] = (fe_df['Cumulative_High_Sev'] / fe_df['Historical_Threat_Count']).round(4)
    fe_df.drop(columns=['Cumulative_High_Sev'], inplace=True)
    
    # ----------------------------------------------------
    # 3. IP Reputation Score
    # ----------------------------------------------------
    logger.info("Calculating IP Reputation Score...")
    sev_weights = fe_df['Severity'].map({'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}).fillna(1)
    act_weights = fe_df['Action_Taken'].map({'Logged': 1.0, 'Alerted': 1.5, 'Blocked': 2.0, 'Isolated': 3.5}).fillna(1.0)
    event_weights = sev_weights * act_weights
    
    fe_df['IP_Reputation_Score'] = fe_df.groupby('Source_IP')['incident_id'].transform(
        lambda x: event_weights.loc[x.index].cumsum()
    )
    # Normalize reputation to max 100 for safety
    max_rep = fe_df['IP_Reputation_Score'].max()
    if max_rep > 0:
        fe_df['IP_Reputation_Score'] = ((fe_df['IP_Reputation_Score'] / max_rep) * 100.0).round(2)
        
    # ----------------------------------------------------
    # 5. Rolling Incident Average
    # ----------------------------------------------------
    logger.info("Calculating system-wide rolling daily averages...")
    fe_df['Date'] = fe_df['Timestamp'].dt.date
    daily_counts = fe_df.groupby('Date').size().reset_index(name='Daily_Incident_Count')
    # 7-day rolling mean
    daily_counts['Rolling_Incident_Average'] = daily_counts['Daily_Incident_Count'].rolling(window=7, min_periods=1).mean().round(2)
    fe_df = pd.merge(fe_df, daily_counts[['Date', 'Rolling_Incident_Average']], on='Date', how='left')
    fe_df.drop(columns=['Date'], inplace=True)

    # ----------------------------------------------------
    # 7. Session Duration Anomaly (Z-Score by Attack Type)
    # ----------------------------------------------------
    logger.info("Calculating Session Duration Anomalies...")
    # Calculate group means and standard deviations
    stats = fe_df.groupby('Attack_Type')['Session_Duration'].agg(['mean', 'std']).reset_index()
    fe_df = pd.merge(fe_df, stats, on='Attack_Type', how='left')
    
    # Z-score formula: (x - mean) / std. Default to 0 if std is 0
    fe_df['Session_Duration_Anomaly'] = (fe_df['Session_Duration'] - fe_df['mean']) / fe_df['std']
    fe_df['Session_Duration_Anomaly'] = fe_df['Session_Duration_Anomaly'].fillna(0.0).round(4)
    fe_df.drop(columns=['mean', 'std'], inplace=True)

    # ----------------------------------------------------
    # 8. Geographic Anomaly Score
    # ----------------------------------------------------
    logger.info("Calculating Geographic Anomaly Score...")
    country_freqs = fe_df['Country'].value_counts(normalize=True).to_dict()
    fe_df['Geographic_Anomaly_Score'] = fe_df['Country'].map(lambda x: 1.0 - country_freqs.get(x, 0.0)).round(4)

    # ----------------------------------------------------
    # 9. User Behaviour Anomaly Score
    # ----------------------------------------------------
    logger.info("Calculating User Behaviour Anomaly Score...")
    role_weights = {
        "Admin": 3.0, "DB Admin": 2.5, "Developer": 2.0, 
        "HR Specialist": 1.5, "Standard Employee": 1.0
    }
    auth_weights = {
        "Password": 1.0, "MFA": 2.0, "SSH Key": 1.5, "API Key": 2.5, "JWT": 1.2
    }
    r_weights = fe_df['User_Role'].map(role_weights).fillna(1.0)
    a_weights = fe_df['Auth_Method'].map(auth_weights).fillna(1.0)
    # Anomaly is elevated by failed logins and credential configurations
    fe_df['User_Behaviour_Anomaly_Score'] = (fe_df['Failed_Login_Count'] * r_weights * a_weights).round(2)

    # ----------------------------------------------------
    # 10. Login Time Anomaly
    # ----------------------------------------------------
    logger.info("Calculating Login Time Anomalies...")
    fe_df['Hour'] = fe_df['Timestamp'].dt.hour
    fe_df['Weekend_Flag'] = fe_df['Timestamp'].dt.weekday.apply(lambda x: 1 if x >= 5 else 0)
    # Anomaly if outside 08:00 - 18:00 or on weekends
    fe_df['Login_Time_Anomaly'] = fe_df.apply(
        lambda r: 1 if (r['Hour'] < 8 or r['Hour'] > 18 or r['Weekend_Flag'] == 1) else 0,
        axis=1
    )

    # ----------------------------------------------------
    # 11. Attack Burst Detection (10-minute bins)
    # ----------------------------------------------------
    logger.info("Calculating Attack Bursts...")
    # Bin by 10-minutes
    fe_df['Bin_10m'] = fe_df['Timestamp'].dt.floor('10min')
    bin_counts = fe_df.groupby('Bin_10m').size().reset_index(name='Bin_Count')
    # Rolling standard deviation and mean over the last 12 bins (2 hours)
    bin_counts['Bin_Mean'] = bin_counts['Bin_Count'].rolling(window=12, min_periods=1).mean()
    bin_counts['Bin_Std'] = bin_counts['Bin_Count'].rolling(window=12, min_periods=1).std().fillna(0)
    
    # Burst flagged if bin count > mean + 1.5 * std
    bin_counts['Attack_Burst_Detection'] = (
        bin_counts['Bin_Count'] > (bin_counts['Bin_Mean'] + 1.5 * bin_counts['Bin_Std'])
    ).astype(int)
    
    fe_df = pd.merge(fe_df, bin_counts[['Bin_10m', 'Attack_Burst_Detection']], on='Bin_10m', how='left')
    fe_df['Attack_Burst_Detection'] = fe_df['Attack_Burst_Detection'].fillna(0).astype(int)
    fe_df.drop(columns=['Bin_10m', 'incident_id'], inplace=True)

    # ----------------------------------------------------
    # Calculate Base Risk Score (Enhanced logic integrating new metrics)
    # ----------------------------------------------------
    logger.info("Recalculating and Normalizing Threat Risk Scores...")
    # Weights for Risk Score calculation:
    # - Severity: Critical=4, High=3, Med=2, Low=1 (x 2.5) [Max = 10]
    # - Failed_Login_Count: (x 0.5) [capped at 5]
    # - Attack Velocity Anomaly: (x 1.2) [capped at 6]
    # - IP Reputation Score: (x 0.1) [Max = 10]
    # - User Behaviour Anomaly: (x 0.2) [capped at 6]
    # Total Max Raw Score ~ 37
    
    sev_mapped = fe_df['Severity'].map({'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}).fillna(1)
    failed_capped = fe_df['Failed_Login_Count'].clip(upper=10)
    velocity_capped = fe_df['Attack_Velocity'].clip(upper=5)
    behaviour_capped = fe_df['User_Behaviour_Anomaly_Score'].clip(upper=30)
    
    raw_risk = (
        (sev_mapped * 2.5) +
        (failed_capped * 0.5) +
        (velocity_capped * 1.2) +
        (fe_df['IP_RepRep'] if 'IP_RepRep' in fe_df else fe_df['IP_Reputation_Score'] * 0.1) +
        (behaviour_capped * 0.2)
    )
    
    # 12. Threat Score Normalization (Scale raw risk to 0-100)
    min_r = raw_risk.min()
    max_r = raw_risk.max()
    if max_r != min_r:
        fe_df['Normalized_Risk_Score'] = (((raw_risk - min_r) / (max_r - min_r)) * 100.0).round(2)
    else:
        fe_df['Normalized_Risk_Score'] = 0.0

    # Categorize Risk Level Target
    def get_risk_level(score: float) -> str:
        if score < 35.0:
            return "Low Risk"
        elif score < 70.0:
            return "Medium Risk"
        else:
            return "High Risk"
            
    fe_df['Risk_Level'] = fe_df['Normalized_Risk_Score'].apply(get_risk_level)

    # 13. Device Risk Score & 14. Country Risk Score (Aggregate historical statistics)
    logger.info("Calculating Device and Country risk scores...")
    device_risk = fe_df.groupby('Device')['Normalized_Risk_Score'].transform('mean').round(2)
    fe_df['Device_Risk_Score'] = device_risk
    
    country_risk = fe_df.groupby('Country')['Normalized_Risk_Score'].transform('mean').round(2)
    fe_df['Country_Risk_Score'] = country_risk
    
    # Cleanup date extraction helper
    fe_df['Month'] = fe_df['Timestamp'].dt.month_name()
    fe_df['Day'] = fe_df['Timestamp'].dt.day_name()
    
    logger.info("Feature engineering calculations completed successfully.")
    return fe_df

def run_feature_engineering_pipeline(input_path: str = "data/processed/cyber_incidents_cleaned.csv",
                                     output_path: str = "data/processed/cyber_incidents_processed.csv") -> pd.DataFrame:
    """Ingests the cleaned dataset, engineers 14 advanced features, and exports results."""
    try:
        df = load_cleaned_data(input_path)
        processed_df = calculate_advanced_features(df)
        
        # Save output
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        processed_df.to_csv(output_path, index=False)
        logger.info(f"Processed dataset saved to: {output_path} (Shape: {processed_df.shape})")
        
        print("\nRisk Level Distribution Post-Feature Engineering:")
        print(processed_df['Risk_Level'].value_counts())
        
        return processed_df
    except Exception as e:
        logger.error(f"Error in feature engineering pipeline: {str(e)}", exc_info=True)
        raise e

if __name__ == "__main__":
    run_feature_engineering_pipeline()
