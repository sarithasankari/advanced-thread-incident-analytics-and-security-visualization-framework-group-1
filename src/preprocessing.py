"""
Data Preprocessing Pipeline
Handles loading datasets, cleaning missing values, removing duplicates,
parsing datetimes, and saving the cleaned intermediate dataset.
"""

import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

def load_data(file_path):
    """Loads the dataset from the specified CSV path. If missing, generates synthetic incidents."""
    if not os.path.exists(file_path):
        print(f"Dataset not found at: {file_path}. Automatically generating synthetic incidents...")
        from src.data_generator import generate_synthetic_incidents
        return generate_synthetic_incidents(num_records=5000, output_path=file_path)
    print(f"Loading raw dataset from: {file_path}")
    return pd.read_csv(file_path)

def clean_data(df):
    """
    Cleans the dataset by:
    - Dropping exact duplicates
    - Parsing Timestamps
    - Imputing missing values if present (impute numeric with median, categoricals with mode)
    """
    df_clean = df.copy()
    
    # 1. Remove duplicates
    initial_rows = len(df_clean)
    df_clean = df_clean.drop_duplicates()
    duplicates_removed = initial_rows - len(df_clean)
    if duplicates_removed > 0:
        print(f"Removed {duplicates_removed} duplicate records.")
    
    # 2. Convert timestamps
    if 'Timestamp' in df_clean.columns:
        df_clean['Timestamp'] = pd.to_datetime(df_clean['Timestamp'], errors='coerce')
        # Drop rows where timestamp couldn't be parsed
        invalid_ts = df_clean['Timestamp'].isna().sum()
        if invalid_ts > 0:
            print(f"Dropping {invalid_ts} rows with invalid Timestamps.")
            df_clean = df_clean.dropna(subset=['Timestamp'])
    
    # 3. Handle missing values (imputation)
    for col in df_clean.columns:
        missing_count = df_clean[col].isna().sum()
        if missing_count > 0:
            print(f"Imputing {missing_count} missing values in column: '{col}'")
            if df_clean[col].dtype in [np.float64, np.int64]:
                median_val = df_clean[col].median()
                df_clean[col] = df_clean[col].fillna(median_val)
            else:
                mode_val = df_clean[col].mode()[0]
                df_clean[col] = df_clean[col].fillna(mode_val)
                
    # 4. Standardize standard fields
    # Ensure Port and Failed_Login_Count are integers
    if 'Port' in df_clean.columns:
        df_clean['Port'] = df_clean['Port'].astype(int)
    if 'Failed_Login_Count' in df_clean.columns:
        df_clean['Failed_Login_Count'] = df_clean['Failed_Login_Count'].astype(int)
        
    return df_clean

def encode_categorical(df, columns_to_encode):
    """
    Encodes categorical columns using Label Encoding.
    Returns a copy of the dataframe with encoded columns and a dict of encoders.
    Used for machine learning features.
    """
    df_encoded = df.copy()
    encoders = {}
    for col in columns_to_encode:
        if col in df_encoded.columns:
            le = LabelEncoder()
            df_encoded[col] = le.fit_transform(df_encoded[col].astype(str))
            encoders[col] = le
    return df_encoded, encoders

def scale_features(df, columns_to_scale):
    """
    Scales numerical columns using Standard Scaler.
    Returns a copy of the dataframe with scaled columns and the scaler.
    """
    df_scaled = df.copy()
    if not columns_to_scale:
        return df_scaled, None
        
    scaler = StandardScaler()
    df_scaled[columns_to_scale] = scaler.fit_transform(df_scaled[columns_to_scale])
    return df_scaled, scaler

def run_preprocessing_pipeline(raw_path="data/raw/cyber_incidents_raw.csv", 
                              cleaned_path="data/processed/cyber_incidents_cleaned.csv"):
    """Runs the full preprocessing pipeline on the raw dataset and saves it."""
    try:
        # Load
        df = load_data(raw_path)
        
        # Clean
        df_clean = clean_data(df)
        
        # Save the clean dataset (retaining human-readable strings for visualization and dashboard)
        os.makedirs(os.path.dirname(cleaned_path), exist_ok=True)
        df_clean.to_csv(cleaned_path, index=False)
        print(f"Preprocessed dataset saved successfully to '{cleaned_path}'. Shape: {df_clean.shape}")
        return df_clean
        
    except Exception as e:
        print(f"Error in preprocessing pipeline: {str(e)}")
        raise e

if __name__ == "__main__":
    run_preprocessing_pipeline()
