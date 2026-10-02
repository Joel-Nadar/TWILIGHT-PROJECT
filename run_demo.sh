#!/bin/bash
# run_demo.sh - One-command startup for Twilight Gateway
# Starts the gateway with all services

set -e

echo "========================================"
echo "Twilight Gateway - Demo Startup"
echo "========================================"
echo ""

# Check if Python is available
if ! command -v python &> /dev/null; then
    echo "Error: Python not found. Please install Python 3.11+"
    exit 1
fi

# Check if required packages are installed
echo "Checking dependencies..."
python -c "import fastapi, uvicorn, pydantic, pynacl, yaml" 2>/dev/null || {
    echo "Error: Required packages not found. Installing..."
    pip install fastapi uvicorn pydantic pydantic-settings pynacl pyyaml python-multipart pytest httpx
}

# Reset database
echo ""
echo "Resetting database..."
python scripts/reset_db.py

# Generate keys if not exists
echo ""
echo "Setting up keys..."
if [ ! -f "keys/gateway_private.pem" ]; then
    python scripts/setup_keys.py
fi

# Sign manifests
echo ""
echo "Signing manifests..."
python scripts/sign_manifests.py

# Start gateway
echo ""
echo "========================================"
echo "Starting Twilight Gateway..."
echo "API Docs: http://127.0.0.1:8000/docs"
echo "WebSocket: ws://127.0.0.1:8000/ws"
echo "Mode: $(grep RUNTIME_MODE .env 2>/dev/null || echo 'on (default)')"
echo "========================================"
echo ""

python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000 --reload
