#!/bin/bash
echo "[+] Starting Background System Noise Generator..."
echo "[+] Training PyTorch to recognize benign network, disk, crypto, and admin tasks."
echo "[+] Press Ctrl+C to stop."

WORK_DIR="/tmp/hids_noise"
mkdir -p "$WORK_DIR"
trap "rm -rf $WORK_DIR; echo -e '\n[+] Cleaned up noise artifacts. Exiting.'; exit" INT

while true; do
    # Pick a random behavior profile (0 to 4)
    ACTION=$((RANDOM % 5))
    
    case $ACTION in
        0)
            # PROFILE 1: Network & DNS Traffic
            curl -s --connect-timeout 2 https://example.com > /dev/null
            ping -c 1 8.8.8.8 > /dev/null
            curl -s -I https://github.com > /dev/null
            ;;
        1)
            # PROFILE 2: Heavy Disk I/O & Archiving (Teaches it that zipping files is normal)
            dd if=/dev/urandom of="$WORK_DIR/data.tmp" bs=1M count=5 2>/dev/null
            cp "$WORK_DIR/data.tmp" "$WORK_DIR/data_copy.tmp"
            tar -czf "$WORK_DIR/archive.tar.gz" -C "$WORK_DIR" data.tmp 2>/dev/null
            rm -f "$WORK_DIR"/*.tmp
            ;;
        2)
            # PROFILE 3: CPU, Cryptography & Hashing (Prevents false positives on crypto/compilation)
            head -c 500000 /dev/urandom > "$WORK_DIR/crypto.tmp"
            sha256sum "$WORK_DIR/crypto.tmp" > /dev/null
            base64 "$WORK_DIR/crypto.tmp" > "$WORK_DIR/crypto.b64"
            rm -f "$WORK_DIR"/crypto*
            ;;
        3)
            # PROFILE 4: Process & System Monitoring (Admin tasks)
            ps aux > /dev/null
            free -m > /dev/null
            df -h > /dev/null
            uptime > /dev/null
            grep -r "root" /etc/ > /dev/null 2>&1
            ;;
        4)
            # PROFILE 5: File Metadata & Permission Changes (Teaches it that chmod isn't always an exploit)
            touch "$WORK_DIR/meta.txt"
            chmod 777 "$WORK_DIR/meta.txt"
            echo "Log entry: $(date)" >> "$WORK_DIR/meta.txt"
            chmod 644 "$WORK_DIR/meta.txt"
            cat "$WORK_DIR/meta.txt" > /dev/null
            rm -f "$WORK_DIR/meta.txt"
            ;;
    esac
    
    # Generate an organic, randomized delay between 0.1 and 0.9 seconds
    # This prevents the AI from learning a fixed timing pattern
    sleep 0.$((RANDOM % 9 + 1))
done