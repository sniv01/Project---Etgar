@echo off
chcp 65001 >nul
echo ============================================================
echo   Etgar Scout V36.0.2 — Background Research Briefing Runner
echo ============================================================
cd /d "%~dp0"
python etgar_scout.py --config etgar_config.json
if errorlevel 1 (
  echo.
  echo [!] Live fetch encountered an error or offline environment.
  echo [!] To generate an offline demo briefing, run:
  echo     python etgar_scout.py --config etgar_config.json --demo-corpus
)
pause
