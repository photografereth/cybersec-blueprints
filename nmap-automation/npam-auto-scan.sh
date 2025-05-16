#!/bin/bash

# nmap-auto-scan.sh
# Automação de varredura com múltiplos formatos de saída e organizacção por data/hora

if [ -z "$1" ]; then
    echo "Uso: $0 <alvo ou rede>"
    exit 1
fi

TARGET=$1
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="scans/scan_$TIMESTAMP"

mkdir -p "$OUTPUT_DIR"

echo "[*] Iniciando scans para $TARGET"
# stealth SYN scan * version detection, sem ping
nmap -sS -sV -T4 -Pn -oA "$OUTPUT_DIR/nmap-output" "$TARGET"

echo "[*] scan completo. Resultados salvos em $OUTPUT_DIR"

# Torne executável com -> chmod +x nmap-auto-scan.sh