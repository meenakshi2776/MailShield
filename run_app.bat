@echo off
cd /d "%~dp0"
call .venv\Scripts\python.exe -m streamlit run app.py --server.headless true
pause
