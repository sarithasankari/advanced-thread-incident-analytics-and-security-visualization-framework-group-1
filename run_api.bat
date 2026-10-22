@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
echo ================================================================
echo Starting Advanced Threat REST API Backend on port 8000...
echo Swagger UI Docs: http://localhost:8000/docs
echo ReDoc:          http://localhost:8000/redoc
echo ================================================================
.\venv\Scripts\python.exe -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
pause
