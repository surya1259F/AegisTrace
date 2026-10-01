#!/bin/bash
set -e

# ADFIR Desktop Application & Core Engine Development Launcher
echo "=========================================================="
echo "    ADFIR - Autonomous Digital Forensics Platform         "
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# 1. Start Python FastAPI Backend Engine
echo "[1/2] Starting ADFIR Forensic Core API on http://127.0.0.1:8000..."
source "$ROOT_DIR/backend/.venv/bin/activate"
export PYTHONPATH="$ROOT_DIR"
python3 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!

trap "echo 'Terminating ADFIR Backend...'; kill $BACKEND_PID" EXIT

sleep 2

# 2. Start Tauri Desktop Shell
echo "[2/2] Launching ADFIR Tauri Desktop Interface..."
cd "$ROOT_DIR/frontend"
npx tauri dev

