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

rem Double-clic DANS le zip : Windows n'extrait que ce .bat dans un dossier
rem temporaire, DexCheck.ps1 n'est pas a cote. On le dit en clair, avant l'UAC.
if not exist "%~dp0DexCheck.ps1" (
    echo.
    echo   Le dossier n'est pas extrait.
    echo.
    echo   1. Ferme cette fenetre.
    echo   2. Clic droit sur le fichier .zip telecharge, puis "Extraire tout".
    echo   3. Ouvre le dossier extrait et double-clique LANCER-LE-CHECK.bat.
    echo.
    pause
    exit /b 1
)

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 2>nul
    rem  "if errorlevel 1" et PAS "if %%errorlevel%% neq 0" : dans un bloc entre
    rem  parentheses, %%errorlevel%% est developpe au PARSING, donc il vaudrait
    rem  encore le code de "net session". "if errorlevel 1" lit la valeur VIVE.
    if errorlevel 1 (
        echo.
        echo   Elevation refusee ou impossible.
        echo   Le check a besoin des droits administrateur pour LIRE le systeme.
        echo   Il ne modifie rien.
        echo.
        echo   Relance ce fichier et clique OUI sur la fenetre bleue de Windows.
        echo.
        pause
    )
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
echo   Ne ferme pas la fenetre avant la fin.
echo.

rem Un seul mode : le check complet. Aucune question.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DexCheck.ps1" -NoElevate -NoPause -Deep

echo.
pause
