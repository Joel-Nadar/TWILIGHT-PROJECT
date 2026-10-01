#!/bin/bash
# Twilight Demo Script
# Resets database, starts gateway, runs baseline scenarios

echo "=================================="
echo "Twilight Backend Demo"
echo "=================================="

# Reset database
echo ""
echo "[1/3] Resetting database..."
python scripts/reset_db.py

# Start gateway in background
echo ""
echo "[2/3] Starting gateway..."
uvicorn gateway.main:app --host 127.0.0.1 --port 8000 &
GATEWAY_PID=$!

# Wait for gateway to start
echo "Waiting for gateway to start..."
sleep 3

# Run baseline scenarios
echo ""
echo "[3/3] Running baseline scenarios..."
python agents/scenarios.py

# Cleanup
echo ""
echo "Demo complete. Stopping gateway..."
kill $GATEWAY_PID

echo "=================================="
echo "Demo finished"
echo "=================================="
