#!/bin/bash
# Hacking Tools Suite - Web Application Launcher
# Run this script to start the Flask web server

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   HACKING TOOLS SUITE - WEB APPLICATION LAUNCHER            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if Flask is installed
python3 -c "import flask" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[!] Flask not installed. Installing dependencies..."
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[!] Failed to install dependencies. Please run:"
        echo "    pip install -r requirements.txt"
        exit 1
    fi
fi

echo "[*] Starting Hacking Tools Suite Web Application..."
echo ""
echo "[*] Access the application at: http://localhost:5000"
echo "[*] Press Ctrl+C to stop the server"
echo ""

python3 app.py

if [ $? -ne 0 ]; then
    echo ""
    echo "[!] Error running the application"
    exit 1
fi
