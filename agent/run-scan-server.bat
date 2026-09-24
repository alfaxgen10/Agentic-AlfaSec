@echo off
cd /d "%~dp0\.."
python -m alfasec.server --allow-root "%cd%"
