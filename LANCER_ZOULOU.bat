@echo off
rem ===========================================================================
rem  Zoulou Scanner - lancement sous Windows (Docker Desktop)
rem  Double-cliquer sur ce fichier. Prerequis : Docker Desktop demarre.
rem ===========================================================================
title Zoulou Scanner
cd /d "%~dp0"

echo.
echo  === Zoulou Scanner ===
echo.

docker info >nul 2>&1
if errorlevel 1 (
  echo  [!] Docker Desktop n'est pas demarre.
  echo      Ouvrez Docker Desktop, attendez qu'il indique "Engine running",
  echo      puis relancez ce fichier.
  echo.
  pause
  exit /b 1
)

docker image inspect security-orchestrator >nul 2>&1
if errorlevel 1 (
  echo  Premiere utilisation : construction de l'image des scanners.
  echo  Cela peut prendre 10 a 20 minutes. Ne fermez pas cette fenetre.
  echo.
  docker compose --profile runner build scanner-runner
  if errorlevel 1 goto :echec
)

echo  Preparation de l'application web (rapide si deja faite)...
docker compose build web
if errorlevel 1 goto :echec

echo  Demarrage...
docker compose up -d
if errorlevel 1 goto :echec

echo  Attente du serveur...
set /a essais=0
:attente
set /a essais+=1
powershell -NoProfile -Command "try { Invoke-WebRequest http://localhost:5000/api/auth/status -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 goto :pret
if %essais% geq 60 goto :echec
timeout /t 2 /nobreak >nul
goto :attente

:pret
start "" http://localhost:5000
echo.
echo  [OK] Zoulou Scanner est lance : http://localhost:5000
echo.
echo  Connexion : utilisateur  admin   /   mot de passe  changeme
echo  Pour un scan : New Scan, choisir le dossier du projet,
echo  cocher les familles d'outils, puis Start Scan.
echo  Pour l'IA (facultatif) : demarrer LM Studio et son serveur local (port 1234).
echo.
echo  Pour tout arreter : double-cliquer sur ARRETER_ZOULOU.bat
echo.
pause
exit /b 0

:echec
echo.
echo  [!] Le lancement a echoue. Copiez les messages ci-dessus
echo      pour obtenir de l'aide.
echo.
pause
exit /b 1
