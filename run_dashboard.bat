@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
echo ================================================================
echo Starting SOC Incident Analytics Portal (Streamlit) on port 8501...
echo Local URL: http://localhost:8501
echo ================================================================
.\venv\Scripts\python.exe -m streamlit run app/dashboard.py --server.port 8501
pause
