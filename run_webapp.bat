@echo off
REM Hacking Tools Suite - Web Application Launcher
REM This script starts the Flask web server

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║   HACKING TOOLS SUITE - WEB APPLICATION LAUNCHER            ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

REM Check if Flask is installed
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [!] Flask not installed. Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [!] Failed to install dependencies. Please run:
        echo     pip install -r requirements.txt
        pause
        exit /b 1
    )
)

echo [*] Starting Hacking Tools Suite Web Application...
echo.
echo [*] Access the application at: http://localhost:5000
echo [*] Press Ctrl+C to stop the server
echo.

python app.py

if errorlevel 1 (
    echo.
    echo [!] Error running the application
    pause
    exit /b 1
)
