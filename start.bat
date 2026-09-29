@echo off
rem Двойной клик: запускает локальный сервер и открывает страницу в браузере.
rem Окно не закрывайте, пока пользуетесь страницей.
chcp 65001 >nul
cd /d "%~dp0"
if not exist node_modules\ssh2 (
  echo Устанавливаю зависимости...
  call npm install --no-fund --no-audit
)
start "" http://127.0.0.1:8080/
node server.js
pause
