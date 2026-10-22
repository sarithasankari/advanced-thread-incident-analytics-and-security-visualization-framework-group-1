@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
echo ================================================================
echo Starting Django SOC Service on port 8000...
echo Admin URL: http://localhost:8000/admin/
echo ================================================================
.\venv\Scripts\python.exe manage.py runserver 0.0.0.0:8000
pause
