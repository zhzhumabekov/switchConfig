@echo off
rem Двойной клик: забрать конфигурацию с коммутатора и обновить страницу.
rem Пример: fetch.bat --host 192.168.1.1 --user admin
chcp 65001 >nul
cd /d "%~dp0"
node fetch-config.js %*
pause
