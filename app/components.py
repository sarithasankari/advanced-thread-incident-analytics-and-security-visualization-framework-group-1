"""
Upgraded Dashboard Components Module
Generates Plotly figures for SOC analytics, time-series forecasting, and SHAP explainability.
"""

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any, List

# Unified color palette for cohesive premium SOC layout
THEME_COLORS = {
    "High Risk": "#EF4444",      # High risk: Red
    "Medium Risk": "#F59E0B",    # Med risk: Amber
    "Low Risk": "#10B981",       # Low risk: Green
    "Background": "#0F172A",     # Slate 900
    "CardBackground": "#1E293B", # Slate 800
    "Primary": "#3B82F6",        # Blue
    "Accent": "#8B5CF6",         # Violet
    "TextLight": "#F8FAFC",      # Slate 50
    "TextMuted": "#94A3B8"       # Slate 400
}

def plot_attack_trend_line(df: pd.DataFrame) -> go.Figure:
    """Generates a line chart showing daily incident volumes over time."""
    df_trend = df.copy()
    df_trend['Date'] = df_trend['Timestamp'].dt.date
    trend = df_trend.groupby('Date').size().reset_index(name='Incidents')
    
    fig = px.line(
        trend, x='Date', y='Incidents',
        title="Daily Security Alerts Trend",
        labels={'Date': 'Date', 'Incidents': 'Alerts Count'},
        color_discrete_sequence=[THEME_COLORS["Primary"]]
    )
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(showgrid=False),
        yaxis=dict(gridcolor='#334155')
    )
    fig.update_traces(line=dict(width=3))
    return fig

def plot_hourly_trend_bar(df: pd.DataFrame) -> go.Figure:
    """Generates a bar chart showing average incident frequency by hour of the day."""
    hourly = df.groupby('Hour').size().reset_index(name='Incidents')
    
    fig = px.bar(
        hourly, x='Hour', y='Incidents',
        title="Incident Frequency by Hour of Day",
        labels={'Hour': 'Hour (24h)', 'Incidents': 'Alerts Count'},
        color_discrete_sequence=[THEME_COLORS["Accent"]]
    )
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(tickmode='linear', showgrid=False),
        yaxis=dict(gridcolor='#334155')
    )
    return fig

def plot_severity_pie(df: pd.DataFrame) -> go.Figure:
    """Generates an interactive pie/donut chart representing incident severity levels."""
    sev_counts = df['Severity'].value_counts().reset_index()
    
    color_map = {
        "Critical": "#DC2626",
        "High": "#EF4444",
        "Medium": "#F59E0B",
        "Low": "#10B981"
    }
    
    fig = px.pie(
        sev_counts, names='Severity', values='count',
        title="Severity Breakdown",
        hole=0.4,
        color='Severity',
        color_discrete_map=color_map
    )
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=40, b=20)
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def plot_top_attacks_bar(df: pd.DataFrame) -> go.Figure:
    """Generates a horizontal bar chart displaying the frequency of top attack vectors."""
    attacks = df['Attack_Type'].value_counts().reset_index()
    attacks = attacks.sort_values(by='count', ascending=True)
    
    fig = px.bar(
        attacks, x='count', y='Attack_Type',
        orientation='h',
        title="Top Attack Vectors Detected",
        labels={'count': 'Number of Incidents', 'Attack_Type': 'Attack Type'},
        color='count',
        color_continuous_scale='Blues'
    )
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(gridcolor='#334155'),
        yaxis=dict(showgrid=False),
        coloraxis_showscale=False
    )
    return fig

def plot_country_choropleth(df: pd.DataFrame) -> go.Figure:
    """Generates a global choropleth map demonstrating country-wise alert concentrations."""
    countries = df['Country'].value_counts().reset_index()
    
    fig = px.choropleth(
        countries, locations='Country', color='count',
        hover_name='Country',
        title="Global Alert Concentration",
        color_continuous_scale=px.colors.sequential.Plasma,
        labels={'count': 'Incidents'}
    )
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        geo=dict(bgcolor='rgba(0,0,0,0)', showframe=False, showcoastlines=True, coastlinecolor='#475569'),
        margin=dict(l=20, r=20, t=40, b=20)
    )
    return fig

def plot_attack_protocol_heatmap(df: pd.DataFrame) -> go.Figure:
    """Generates an attack vector vs network protocol correlation heatmap."""
    ct = pd.crosstab(df['Attack_Type'], df['Protocol'])
    
    fig = px.imshow(
        ct,
        title="Attack Vector vs. Network Protocol Heatmap",
        labels=dict(x="Protocol", y="Attack Type", color="Incident Frequency"),
        color_continuous_scale="Viridis",
        aspect="auto"
    )
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=40, b=20)
    )
    return fig

# ==========================================
# ADVANCED VISUALIZATIONS (TASK 13 UPGRADE)
# ==========================================

def plot_forecasting_line(forecast_df: pd.DataFrame, historical_df: pd.DataFrame) -> go.Figure:
    """
    Plots historical daily incident counts alongside ARIMA forecasted trends
    with shaded 95% confidence intervals boundaries.
    """
    historical_df['Date'] = pd.to_datetime(historical_df['Timestamp']).dt.date
    hist_daily = historical_df.groupby('Date').size().reset_index(name='Count')
    hist_daily = hist_daily.sort_values(by='Date').tail(60) # show last 60 days
    
    fig = go.Figure()

    # 1. Historical Actual Line
    fig.add_trace(go.Scatter(
        x=hist_daily['Date'], y=hist_daily['Count'],
        name="Historical Actual",
        line=dict(color=THEME_COLORS["Primary"], width=2.5)
    ))

    # 2. Shaded Confidence Interval (Upper & Lower bounds)
    # To do shaded area in Plotly go.Scatter, we plot Upper and Lower lines,
    # utilizing the 'tonexty' fill parameter.
    x_forecast = forecast_df['Date']
    y_forecast = forecast_df['Forecasted_Count']
    y_lower = forecast_df['Lower_Bound']
    y_upper = forecast_df['Upper_Bound']

    # Upper bound line
    fig.add_trace(go.Scatter(
        x=x_forecast, y=y_upper,
        line=dict(width=0),
        showlegend=False,
        name="Upper CI Boundary"
    ))

    # Lower bound line filled to upper
    fig.add_trace(go.Scatter(
        x=x_forecast, y=y_lower,
        fill='tonexty',
        fillcolor='rgba(139, 92, 246, 0.15)', # Light violet fill
        line=dict(width=0),
        showlegend=False,
        name="Lower CI Boundary"
    ))

    # 3. Forecast Trend line
    fig.add_trace(go.Scatter(
        x=x_forecast, y=y_forecast,
        name="ARIMA Forecast Projection",
        line=dict(color=THEME_COLORS["Accent"], width=3, dash='dash')
    ))

    fig.update_layout(
        template="plotly_dark",
        title="30-Day Cybersecurity Alert Volume Forecast",
        xaxis_title="Date",
        yaxis_title="Incident Count",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=50, b=20),
        xaxis=dict(showgrid=False),
        yaxis=dict(gridcolor='#334155')
    )
    return fig

def plot_shap_waterfall(feature_impacts: Dict[str, float]) -> go.Figure:
    """
    Renders a clean horizontal bar chart of local SHAP attributions.
    Positive values (red) push risk higher, negative values (green) reduce risk.
    """
    # Sort features by impact value
    sorted_features = sorted(feature_impacts.items(), key=lambda x: abs(x[1]), reverse=True)[:12] # show top 12
    sorted_features = sorted_features[::-1] # reverse for horizontal alignment
    
    feats = [item[0] for item in sorted_features]
    impacts = [item[1] for item in sorted_features]
    
    # Define color mappings based on positive/negative signs
    colors = [THEME_COLORS["High Risk"] if v > 0.0 else THEME_COLORS["Low Risk"] for v in impacts]

    fig = go.Figure(go.Bar(
        x=impacts,
        y=feats,
        orientation='h',
        marker_color=colors
    ))

    fig.update_layout(
        template="plotly_dark",
        title="SHAP Local Feature Attributions (Risk Drivers)",
        xaxis_title="SHAP Value (Risk Contribution)",
        yaxis_title="Telemetry Features",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=50, b=20),
        xaxis=dict(gridcolor='#334155'),
        yaxis=dict(showgrid=False)
    )
    return fig

def plot_model_comparison_bar(metrics_dict: Dict[str, Any]) -> go.Figure:
    """Generates a comparison bar chart of the model performance metrics (Accuracy & F1)."""
    model_names = []
    accuracies = []
    f1_scores = []
    
    for model_name, metrics in metrics_dict.items():
        model_names.append(model_name)
        accuracies.append(metrics["accuracy"])
        f1_scores.append(metrics["f1_score"])
        
    df_plot = pd.DataFrame({
        "Model": model_names * 2,
        "Score": accuracies + f1_scores,
        "Metric": ["Accuracy"] * len(model_names) + ["F1-Score"] * len(model_names)
    })
    
    fig = px.bar(
        df_plot, x="Model", y="Score", color="Metric",
        barmode="group",
        title="Model Performance Comparison Summary",
        color_discrete_sequence=[THEME_COLORS["Primary"], THEME_COLORS["Accent"]]
    )
    
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(showgrid=False),
        yaxis=dict(gridcolor='#334155', range=[0, 1.05])
    )
    return fig
