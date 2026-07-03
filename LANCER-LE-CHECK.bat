@echo off
title DexCheck - PC Check
cd /d "%~dp0"

rem Retire l'etiquette "fichier venu d'internet" (Mark-of-the-Web) de tout le
rem dossier -> plus d'avertissement SmartScreen aux lancements suivants, sans
rem aucune signature de code.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0' -Recurse -Force -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1

echo.
echo   DEXCHECK - PC CHECK
echo   ==================
echo.
echo   A faire en partage d'ecran avec un responsable Warzup.
echo   Le check LIT ton PC et produit un rapport. Il ne modifie rien.
echo.
echo   Une fenetre bleue (UAC) va demander l'autorisation admin : clique OUI.
echo   (necessaire pour lire l'historique des suppressions, les journaux...)
echo.

set "NONCE="
set /p "NONCE=  Mot dicte par le moderateur (laisse vide + Entree si aucun) : "

if defined NONCE (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DexCheck.ps1" -Nonce "%NONCE%"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DexCheck.ps1"
)
