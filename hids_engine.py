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
import ctypes
import shutil
from bcc import BPF


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


# eBPF C program running in kernel space
EBPF_EXECVEAT_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall_type[16];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    struct exec_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    __builtin_memcpy(event.syscall_type, "execveat", 9);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    __builtin_memcpy(event.syscall_type, "execve", 7);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

class ExecEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
        ("syscall_type", ctypes.c_char * 16),
    ]

class HidsEbpfExecutionMonitor(threading.Thread):
    def __init__(self, sha256_engine: HidsSha256Engine, yara_engine: HidsYaraEngine):
        super().__init__(daemon=True)
        self.engine = sha256_engine
        self.yara_engine = yara_engine
        self.running = True
        self.bpf = None

    def run(self):
        print("[+] Compiling and loading eBPF kernel probes (execve & execveat)...")
        try:
            self.bpf = BPF(text=EBPF_EXECVEAT_PROGRAM)
            self.bpf["exec_events"].open_perf_buffer(self._handle_event)
            print("[+] eBPF kernel execution trap active and listening to perf ring buffer.")
        except Exception as e:
            print(f"[-] Failed to load eBPF probe: {e}")
            return

        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except Exception:
                break

    def _handle_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(ExecEvent)).contents
        raw_filename = event.filename.decode("utf-8", errors="ignore").strip()
        syscall_used = event.syscall_type.decode("utf-8", errors="ignore").strip()
        comm = event.comm.decode("utf-8", errors="ignore").strip()

        if not raw_filename:
            return

        resolved_path = raw_filename
        if not os.path.isabs(resolved_path):
            found_binary = shutil.which(resolved_path)
            if found_binary:
                resolved_path = found_binary

        if Path(resolved_path).is_file():
            self._scan_execution(resolved_path, comm, event.pid, syscall_used)

    def _scan_execution(self, binary_path: str, comm: str, pid: int, syscall_used: str):
        try:
            file_hash = self.engine.calculate_sha256(binary_path)
            malware_name = self.engine.lookup_hash(file_hash)

            if malware_name:
                print(f"[!!!] MALICIOUS PROCESS (TIER 1): {binary_path} via {syscall_used}")
                return

            yara_match = self.yara_engine.scan_file(binary_path)
            if yara_match:
                print(f"[!!!] MALICIOUS PROCESS (TIER 2): {binary_path} via {syscall_used}")
                return

        except Exception:
            pass

    def stop(self):
        self.running = False


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

    # 3. Initialize eBPF Execution Monitoring Thread
    exec_monitor = HidsEbpfExecutionMonitor(sha256_engine, yara_engine)
    exec_monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping HIDS Engine...")
        exec_monitor.stop()
        for o in observers:
            o.stop()
        for o in observers:
            o.join()


if __name__ == "__main__":
    start_hids()