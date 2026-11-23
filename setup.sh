#!/usr/bin/env bash
# Cerberus Saga — environment setup script (Blueprint Volume 6)
set -euo pipefail

echo "[*] Creating Python virtual environment..."
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate

echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Checking optional scanner binaries..."
command -v nmap   >/dev/null && echo "    nmap: FOUND" || echo "    nmap: MISSING (fallback TCP scan will be used)"
command -v nuclei >/dev/null && echo "    nuclei: FOUND" || echo "    nuclei: MISSING (embedded CVE signatures will be used)"

echo
echo "[+] Setup complete. To run the demo:"
echo "    source venv/bin/activate && python cerberus.py demo"
