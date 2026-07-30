import hashlib
import json
import os
import subprocess
import sqlite3
import time
import threading
import yara
from datetime import datetime, timezone
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class HidsSha256Engine:
    def __init__(self, db_path: str = "hids_signatures.db"):
        self.db_path = db_path

    def inject_test_signature(self):
        """Injects a harmless text file's hash so you can safely test the pipeline."""
        test_string = b"HIDS_THESIS_TEST_PAYLOAD"
        test_hash = hashlib.sha256(test_string).hexdigest()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO mal_hashes (sha256, malware_name) VALUES (?, ?)",
                (test_hash, "Linux.Test.ThesisPayload")
            )
            conn.commit()
        return test_hash

    def calculate_sha256(self, file_path: str, chunk_size: int = 65536) -> str:
        """Streams file binary data in 64KB blocks to keep memory flat."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def lookup_hash(self, sha256_hex: str) -> str | None:
        """Queries the indexed SQLite database for a match."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT malware_name FROM mal_hashes WHERE sha256 = ?",
                    (sha256_hex.lower(),),
                )
                result = cursor.fetchone()
                return result[0] if result else None
        except sqlite3.Error as e:
            print(f"[-] Database lookup error: {e}")
            return None


class HidsYaraEngine:
    def __init__(self, rules_dir: str = "yara_rules"):
        self.rules_dir = rules_dir
        self.rules = self._load_rules()

    def _load_rules(self):
        """Recursively loads and compiles an entire directory of YARA rules using namespacing."""
        if not os.path.isdir(self.rules_dir):
            print(f"[-] YARA rules directory missing: {self.rules_dir}")
            return None
        
        rule_files = {}
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    filepath = os.path.join(root, file)
                    # Use filename as namespace to prevent internal rule identifier collisions
                    rule_files[file] = filepath

        if not rule_files:
            print(f"[-] No YARA rules found in {self.rules_dir}")
            return None

        try:
            print(f"[+] Compiling {len(rule_files)} YARA rule files from {self.rules_dir}...")
            return yara.compile(filepaths=rule_files)
        except yara.SyntaxError as e:
            print(f"\n[-] YARA Compilation Error!\n{e}")
            return None

    def scan_file(self, file_path: str) -> str | None:
        """Scans a target file payload against the compiled YARA ruleset."""
        if not self.rules:
            return None
        try:
            matches = self.rules.match(file_path)
            if matches:
                # Returns 'Namespace -> Rule_Name'
                return f"{matches[0].namespace} -> {matches[0].rule}"
        except Exception as e:
            print(f"[-] YARA scan error on {file_path}: {e}")
        return None


class HidsExecutionMonitor(threading.Thread):
    """Runs in a background thread to intercept kernel execution events via auditd."""
    
    def __init__(self, sha256_engine: HidsSha256Engine, yara_engine: HidsYaraEngine):
        super().__init__(daemon=True)
        self.engine = sha256_engine
        self.yara_engine = yara_engine
        self.audit_log_path = "/var/log/audit/audit.log"
        
        # Automatically arm the kernel trap when the thread initializes
        self.ensure_kernel_trap_is_armed()

    def ensure_kernel_trap_is_armed(self):
        """Checks if the custom auditd rule is active, and injects it if missing."""
        try:
            current_rules = subprocess.check_output(["sudo", "auditctl", "-l"], text=True)
            
            if "hids_execution_trap" not in current_rules:
                print("[*] HIDS kernel trap not found. Injecting rule automatically...")
                subprocess.run([
                    "sudo", "auditctl", 
                    "-a", "always,exit", 
                    "-F", "arch=b64", 
                    "-S", "execve", 
                    "-k", "hids_execution_trap"
                ], check=True)
                print("[+] Kernel execution trap successfully armed.")
            else:
                print("[*] Kernel execution trap already active.")
                
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to configure auditd rules: {e}")
        except FileNotFoundError:
            print("[-] auditctl binary not found. Is the 'audit' package installed?")

    def run(self):
        print(f"[+] Hooking into kernel auditd stream for execution events...")
        if not os.path.exists(self.audit_log_path):
            print(f"[-] Audit log not found at {self.audit_log_path}. Ensure auditd is installed and running.")
            return
            
        with open(self.audit_log_path, "r") as f:
            f.seek(0, 2) # Jump to the end of the file
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                if "hids_execution_trap" in line and "type=EXECVE" in line:
                    self.parse_and_scan(line)

    def parse_and_scan(self, log_line: str):
        """Extracts the executable path and chains it through Tier 1 and Tier 2 scanning logic."""
        try:
            parts = log_line.split(" ")
            for part in parts:
                if part.startswith('a0="'):
                    binary_path = part[4:-1]
                    
                    if Path(binary_path).exists():
                        print(f"\n[*] Process Execution Intercepted: {binary_path}")
                        
                        # --- TIER 1: HASH LOOKUP ---
                        file_hash = self.engine.calculate_sha256(binary_path)
                        malware_name = self.engine.lookup_hash(file_hash)
                        
                        if malware_name:
                            alert = {
                                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                                "engine_tier": "EXECUTION_INTERCEPT_HASH",
                                "status": "ALERT",
                                "file_path": binary_path,
                                "calculated_hash": file_hash,
                                "signature_match": malware_name,
                                "action_taken": "DETECTED",
                            }
                            print(f"[!!!] MALICIOUS PROCESS EXECUTION DETECTED (TIER 1) [!!!]\n{json.dumps(alert, indent=4)}")
                            break

                        # --- TIER 2: YARA PATTERN MATCHING ---
                        yara_match = self.yara_engine.scan_file(binary_path)
                        if yara_match:
                            alert = {
                                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                                "engine_tier": "EXECUTION_INTERCEPT_HEURISTIC",
                                "status": "ALERT",
                                "file_path": binary_path,
                                "calculated_hash": file_hash,
                                "signature_match": yara_match,
                                "action_taken": "DETECTED",
                            }
                            print(f"[!!!] MALICIOUS PROCESS EXECUTION DETECTED (TIER 2) [!!!]\n{json.dumps(alert, indent=4)}")
                            break
                            
                        print(f"[*] Executed binary verified clean across Tier 1 & Tier 2.")
                    break
        except Exception:
            pass


class HidsHandler(FileSystemEventHandler):
    def __init__(self, sha256_engine: HidsSha256Engine, yara_engine: HidsYaraEngine):
        self.engine = sha256_engine
        self.yara_engine = yara_engine
        self.recent_events = {}

    def process_file(self, file_path: str):
        if not os.path.isfile(file_path):
            return

        current_time = time.time()
        if file_path in self.recent_events and (current_time - self.recent_events[file_path]) < 1.0:
            return
        self.recent_events[file_path] = current_time

        try:
            # --- TIER 1: SHA256 Signature Scan ---
            file_hash = self.engine.calculate_sha256(file_path)
            malware_name = self.engine.lookup_hash(file_hash)

            if malware_name:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "engine_tier": "SHA256_SIGNATURE",
                    "status": "ALERT",
                    "file_path": str(Path(file_path).resolve()),
                    "calculated_hash": file_hash,
                    "signature_match": malware_name,
                    "action_taken": "DETECTED",
                }
                print(f"\n[!!!] MALICIOUS FILE DROP DETECTED (TIER 1) [!!!]\n{json.dumps(alert, indent=4)}")
                return

            # --- TIER 2: YARA Heuristic Scan ---
            yara_match = self.yara_engine.scan_file(file_path)
            if yara_match:
                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "engine_tier": "YARA_HEURISTICS",
                    "status": "ALERT",
                    "file_path": str(Path(file_path).resolve()),
                    "calculated_hash": file_hash,
                    "signature_match": yara_match,
                    "action_taken": "DETECTED",
                }
                print(f"\n[!!!] MALICIOUS PATTERN DROP DETECTED (TIER 2) [!!!]\n{json.dumps(alert, indent=4)}")
                return
                
            print(f"[*] File drop clean across deterministic layers: {file_path}")

        except (PermissionError, FileNotFoundError):
            pass
        except Exception as e:
            print(f"[-] Error processing {file_path}: {e}")

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)


def start_hids():
    sha256_engine = HidsSha256Engine("hids_signatures.db")
    yara_engine = HidsYaraEngine("yara_rules")
    
    test_hash = sha256_engine.inject_test_signature()
    print(f"[*] Test signature injected. Hash: {test_hash}")

    # 1. Define high risk threat zones 
    home_dir = os.path.expanduser("~")
    
    watch_directories = [
        # --- Staging & Dropper Zones (World-Writable) ---
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run",
        
        # --- User-Space Persistence & Drop Zones ---
        os.path.join(home_dir, "Downloads"),
        os.path.join(home_dir, ".ssh"),
        os.path.join(home_dir, ".config/autostart"),
        os.path.join(home_dir, ".config/systemd/user"),
        
        # --- Root / System-Wide Persistence Zones ---
        "/etc/cron.d",
        "/var/spool/cron",
        "/etc/systemd/system",
        "/usr/local/bin"
    ]

    # 2. Initialize Multi-Zone Filesystem Monitoring
    handler = HidsHandler(sha256_engine, yara_engine)
    observers = []
    print("[+] Initializing multi-zone filesystem hooks...")
    
    for directory in watch_directories:
        try:
            # Ensure safe user/staging directories exist before attaching the hook
            os.makedirs(directory, exist_ok=True)
            observer = Observer()
            observer.schedule(handler, path=directory, recursive=True)
            observer.start()
            observers.append(observer)
            print(f"  -> Hooked zone: {directory}")
        except PermissionError:
            print(f"  [-] Permission denied for zone: {directory} (run with sudo)")
        except Exception as e:
            print(f"  [-] Skipped zone {directory}: {e}")

    # 3. Initialize Auditd Execution Monitoring Thread
    exec_monitor = HidsExecutionMonitor(sha256_engine, yara_engine)
    exec_monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping HIDS Engine...")
        for o in observers:
            o.stop()
        for o in observers:
            o.join()


if __name__ == "__main__":
    start_hids()