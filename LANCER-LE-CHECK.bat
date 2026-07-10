@echo off
title DexCheck - PC Check

rem ============================================================================
rem  Le .bat est le SEUL responsable de l'elevation. S'il n'est pas admin, il se
rem  relance en admin puis quitte l'instance non-admin : une seule fenetre.
rem  DexCheck.ps1 est ensuite appele avec -NoElevate pour qu'il ne relance PAS
rem  une deuxieme fois -- c'est ce double mecanisme d'elevation qui ouvrait une
rem  fenetre qui se refermait aussitot. Le pause final garde la fenetre ouverte
rem  quoi qu'il arrive : rien ne disparait dans le dos du moderateur.
rem ============================================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

rem Retire l'etiquette "venu d'internet" (Mark-of-the-Web) de tout le dossier ->
rem plus d'avertissement SmartScreen, sans aucune signature de code.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0' -Recurse -Force -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1

echo.
echo   DEXCHECK - PC CHECK
echo   ==================
echo.
echo   A faire en partage d'ecran avec un responsable Warzup.
echo   Le check LIT ton PC et produit un rapport. Il ne modifie rien.
echo.

set "NONCE="
set /p "NONCE=  Mot dicte par le moderateur (laisse vide + Entree si aucun) : "

set "DEEP="
set /p "DEEP=  Mode approfondi ? (uniquement si un responsable le demande - plus long) [o/N] : "

set "DEEPFLAG="
if /i "%DEEP%"=="o"   set "DEEPFLAG= -Deep"
if /i "%DEEP%"=="oui" set "DEEPFLAG= -Deep"
if /i "%DEEP%"=="y"   set "DEEPFLAG= -Deep"

echo.
if defined NONCE (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DexCheck.ps1" -NoElevate -Nonce "%NONCE%"%DEEPFLAG%
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DexCheck.ps1" -NoElevate%DEEPFLAG%
)

echo.
pause
