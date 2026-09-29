@echo off
rem Двойной клик: следит за 3floor.txt и пересобирает config.js при каждом сохранении.
chcp 65001 >nul
cd /d "%~dp0"
node update-config.js --watch
pause
