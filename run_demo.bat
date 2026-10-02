@echo off
REM run_demo.bat - One-command startup for Twilight Gateway (Windows)
REM Starts the gateway with all services

echo ========================================
echo Twilight Gateway - Demo Startup
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Please install Python 3.11+
    exit /b 1
)

REM Check if required packages are installed
echo Checking dependencies...
python -c "import fastapi, uvicorn, pydantic, pynacl, yaml" >nul 2>&1
if errorlevel 1 (
    echo Error: Required packages not found. Installing...
    pip install fastapi uvicorn pydantic pydantic-settings pynacl pyyaml python-multipart pytest httpx
)

REM Reset database
echo.
echo Resetting database...
python scripts/reset_db.py

REM Generate keys if not exists
echo.
echo Setting up keys...
if not exist "keys\gateway_private.pem" (
    python scripts/setup_keys.py
)

REM Sign manifests
echo.
echo Signing manifests...
python scripts/sign_manifests.py

REM Start gateway
echo.
echo ========================================
echo Starting Twilight Gateway...
echo API Docs: http://127.0.0.1:8000/docs
echo WebSocket: ws://127.0.0.1:8000/ws
echo Mode: Default (on)
echo ========================================
echo.

python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000 --reload
