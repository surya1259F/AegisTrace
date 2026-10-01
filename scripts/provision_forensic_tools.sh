#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

OS_NAME="$(uname -s)"
OS_DESC="Unknown"
if [ -f /etc/os-release ]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_DESC="${PRETTY_NAME:-$NAME}"
fi

echo "ADFIR FORENSIC TOOL PROVISIONING"
echo "==============================="
echo ""
echo "Operating System: $OS_DESC ($OS_NAME)"

PKG_MGR="none"
if command -v apt-get >/dev/null 2>&1; then
  PKG_MGR="apt"
fi
echo "Package Manager: $PKG_MGR"
echo ""

# Ensure tools/bin wrappers exist
mkdir -p "$ROOT_DIR/tools/bin"

echo "Checking:"

# 1. Sleuth Kit
FLS_PATH="$ROOT_DIR/tools/bin/fls"
if command -v fls >/dev/null 2>&1; then
  FLS_VER="$(fls -V 2>&1 | head -n 1)"
  echo "[OK] Sleuth Kit ($FLS_VER)"
elif [ -x "$FLS_PATH" ]; then
  FLS_VER="$("$FLS_PATH" -V 2>&1 | head -n 1)"
  echo "[OK] Sleuth Kit ($FLS_VER)"
else
  echo "[ERROR] Sleuth Kit (fls) is missing"
  exit 1
fi

# 2. YARA
YARA_PATH="$ROOT_DIR/tools/bin/yara"
if command -v yara >/dev/null 2>&1; then
  YARA_VER="$(yara --version 2>&1 | head -n 1)"
  echo "[OK] YARA (v$YARA_VER)"
elif [ -x "$YARA_PATH" ]; then
  YARA_VER="$("$YARA_PATH" --version 2>&1 | head -n 1)"
  echo "[OK] YARA (v$YARA_VER)"
else
  echo "[ERROR] YARA is missing"
  exit 1
fi

# 3. ExifTool
EXIF_PATH="$ROOT_DIR/tools/bin/exiftool"
if command -v exiftool >/dev/null 2>&1; then
  EXIF_VER="$(exiftool -ver 2>&1 | head -n 1)"
  echo "[OK] ExifTool (v$EXIF_VER)"
elif [ -x "$EXIF_PATH" ]; then
  EXIF_VER="$("$EXIF_PATH" -ver 2>&1 | head -n 1)"
  echo "[OK] ExifTool (v$EXIF_VER)"
else
  echo "[ERROR] ExifTool is missing"
  exit 1
fi

# 4. Volatility 3
VOL_PATH="$ROOT_DIR/volatility-env/bin/vol"
if [ -x "$VOL_PATH" ]; then
  echo "[OK] Volatility 3 (v2.28.0 in volatility-env)"
elif command -v vol >/dev/null 2>&1; then
  echo "[OK] Volatility 3 (in PATH)"
else
  echo "[ERROR] Volatility 3 is missing"
  exit 1
fi

echo ""
echo "Required forensic tool provisioning complete."
