"""
Time-Series Forecasting Module
Uses statsmodels ARIMA to forecast daily, weekly, and monthly security incident counts
along with 95% confidence intervals to identify future attack trends.
"""

import os
import sys
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

# Path configuration for direct execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from statsmodels.tsa.arima.model import ARIMA
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger("forecasting")

def load_processed_data(file_path: str = "data/processed/cyber_incidents_processed.csv") -> pd.DataFrame:
    """Loads the processed dataset containing timestamps."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Processed dataset not found at: {file_path}")
    return pd.read_csv(file_path)

def generate_forecasts(steps: int = 30) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Fits an ARIMA model on daily incident counts and forecasts daily volume.
    Also returns aggregated weekly and monthly projections.
    """
    logger.info("Starting time-series forecasting pipeline...")
    
    # 1. Load and aggregate daily data
    df = load_processed_data()
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df['Date'] = df['Timestamp'].dt.date
    
    # Daily counts
    daily_series = df.groupby('Date').size().reset_index(name='Actual_Count')
    daily_series = daily_series.sort_values(by='Date').reset_index(drop=True)
    
    # Ensure a continuous date range index to prevent statsmodels gaps warnings
    daily_series['Date'] = pd.to_datetime(daily_series['Date'])
    daily_series = daily_series.set_index('Date')
    daily_series = daily_series.asfreq('D', fill_value=0)
    
    # 2. Fit ARIMA Model
    # Order (1,1,1) is a standard baseline that handles trend and autocorrelations well
    logger.info("Fitting ARIMA(1,1,1) model on daily incident series...")
    try:
        model = ARIMA(daily_series['Actual_Count'], order=(1,1,1))
        model_fit = model.fit()
        
        # 3. Forecast
        forecast_res = model_fit.get_forecast(steps=steps)
        forecast_frame = forecast_res.summary_frame(alpha=0.05) # 95% CI (alpha=0.05)
        
        # Rename columns for clarity
        forecast_df = forecast_frame.rename(columns={
            'mean': 'Forecasted_Count',
            'mean_ci_lower': 'Lower_Bound',
            'mean_ci_upper': 'Upper_Bound'
        })
        
        # Ensure values are non-negative and rounded as integer incident counts
        forecast_df = forecast_df.clip(lower=0).round(2)
        
        # Create dates index
        forecast_dates = pd.date_range(start=daily_series.index[-1] + pd.Timedelta(days=1), periods=steps, freq='D')
        forecast_df.index = forecast_dates
        forecast_df = forecast_df.reset_index().rename(columns={'index': 'Date'})
        
        logger.info(f"Daily forecast completed for the next {steps} days.")
        
        # 4. Aggregate weekly and monthly forecasts
        # Daily forecast sum
        daily_forecast_sum = float(forecast_df['Forecasted_Count'].sum())
        
        # Weekly projections (first 7 days)
        weekly_forecast = float(forecast_df['Forecasted_Count'].head(7).sum())
        weekly_lower = float(forecast_df['Lower_Bound'].head(7).sum())
        weekly_upper = float(forecast_df['Upper_Bound'].head(7).sum())
        
        # Monthly projections (30 days)
        monthly_forecast = float(forecast_df['Forecasted_Count'].head(30).sum())
        monthly_lower = float(forecast_df['Lower_Bound'].head(30).sum())
        monthly_upper = float(forecast_df['Upper_Bound'].head(30).sum())
        
        aggregates = {
            "weekly": {
                "forecast": round(weekly_forecast, 2),
                "lower_bound": round(weekly_lower, 2),
                "upper_bound": round(weekly_upper, 2)
            },
            "monthly": {
                "forecast": round(monthly_forecast, 2),
                "lower_bound": round(monthly_lower, 2),
                "upper_bound": round(monthly_upper, 2)
            }
        }
        
        return forecast_df, aggregates

    except Exception as e:
        logger.error(f"Time-series modeling failed: {str(e)}", exc_info=True)
        # Fallback if statsmodels fails or has insufficient data
        logger.info("Falling back to rolling mean extrapolation...")
        avg_daily = float(daily_series['Actual_Count'].mean())
        std_daily = float(daily_series['Actual_Count'].std()) if len(daily_series) > 1 else 1.0
        
        forecast_dates = pd.date_range(start=daily_series.index[-1] + pd.Timedelta(days=1), periods=steps, freq='D')
        fallback_data = []
        for i in range(steps):
            fallback_data.append({
                "Date": forecast_dates[i],
                "Forecasted_Count": round(avg_daily, 2),
                # Expand confidence intervals as time delta increases
                "Lower_Bound": round(max(0.0, avg_daily - 1.96 * std_daily * np.sqrt(i + 1)), 2),
                "Upper_Bound": round(avg_daily + 1.96 * std_daily * np.sqrt(i + 1), 2)
            })
            
        forecast_df = pd.DataFrame(fallback_data)
        
        weekly_val = avg_daily * 7
        monthly_val = avg_daily * 30
        
        aggregates = {
            "weekly": {
                "forecast": round(weekly_val, 2),
                "lower_bound": round(max(0.0, weekly_val - 1.96 * std_daily * np.sqrt(7)), 2),
                "upper_bound": round(weekly_val + 1.96 * std_daily * np.sqrt(7), 2)
            },
            "monthly": {
                "forecast": round(monthly_val, 2),
                "lower_bound": round(max(0.0, monthly_val - 1.96 * std_daily * np.sqrt(30)), 2),
                "upper_bound": round(monthly_val + 1.96 * std_daily * np.sqrt(30), 2)
            }
        }
        return forecast_df, aggregates

if __name__ == "__main__":
    try:
        f_df, agg = generate_forecasts()
        print("Forecast Aggregates:")
        print(agg)
        print("\nFirst 5 Days Forecast:")
        print(f_df.head())
    except Exception as e:
        print(f"Main execution failed: {str(e)}")
