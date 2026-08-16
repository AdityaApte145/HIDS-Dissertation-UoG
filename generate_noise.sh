#!/bin/bash
echo "[+] Starting Background System Noise Generator..."
echo "[+] Press Ctrl+C to stop."

WORK_DIR="/tmp/hids_noise"
mkdir -p "$WORK_DIR"
trap "rm -rf $WORK_DIR; echo -e '\n[+] Cleaned up noise artifacts. Exiting.'; exit" INT

while true; do
    # Network calls
    curl -s --connect-timeout 2 https://example.com > /dev/null
    ping -c 1 8.8.8.8 > /dev/null

    # Disk & Memory I/O
    dd if=/dev/urandom of="$WORK_DIR/data.tmp" bs=1M count=5 2>/dev/null
    cp "$WORK_DIR/data.tmp" "$WORK_DIR/data_copy.tmp"
    grep -r "root" /etc/ > /dev/null 2>&1
    
    # Process Lifecycle
    ps aux > /dev/null
    free -m > /dev/null
    
    rm -f "$WORK_DIR"/*
    
    # Random organic delay (0-2 seconds)
    sleep $((RANDOM % 3))
done