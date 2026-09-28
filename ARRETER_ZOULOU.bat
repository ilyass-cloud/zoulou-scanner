@echo off
rem Zoulou Scanner - arret de l'application (les resultats sont conserves).
title Zoulou Scanner - arret
cd /d "%~dp0"
docker compose down
echo.
echo  Zoulou Scanner est arrete.
echo.
pause
