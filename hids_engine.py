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
import signal

def map_mitre_attack(engine_tier: str, detection_context: str, match_name: str) -> dict:
    match_lower = match_name.lower()
    
    if detection_context == "PROCESS_EXECUTION":
        mitre_data = {
            "tactic": "Execution",
            "technique_id": "T1204.002",
            "technique_name": "User Execution: Malicious File"
        }
        if any(term in match_lower for term in ["sh", "bash", "script", "python"]):
            mitre_data = {
                "tactic": "Execution",
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell"
            }
    else:  # FILE_DROP
        mitre_data = {
            "tactic": "Defense Evasion",
            "technique_id": "T1027",
            "technique_name": "Obfuscated/Compromised Files or Information"
        }
        if any(term in match_lower for term in ["mirai", "botnet", "gafgyt", "tsunami"]):
            mitre_data = {
                "tactic": "Impact / Command and Control",
                "technique_id": "T1498 / T1071",
                "technique_name": "Network Denial of Service / Application Layer Protocol"
            }
        elif "webshell" in match_lower:
            mitre_data = {
                "tactic": "Persistence",
                "technique_id": "T1505.003",
                "technique_name": "Server Software Component: Web Shell"
            }

    return mitre_data

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
        """Scans target file with timeout and prioritizes specific malware rules over generic ones."""
        if not self.rules:
            return None
        try:
            matches = self.rules.match(file_path, timeout=2)
            if not matches:
                return None

            # Prioritize high-fidelity rules over generic utility matchers
            for match in matches:
                ns = match.namespace.lower()
                r = match.rule.lower()
                if not ns.startswith("utils_") and "generic" not in r:
                    return f"{match.namespace} -> {match.rule}"

            return f"[GENERIC] {matches[0].namespace} -> {matches[0].rule}"

        except yara.TimeoutError:
            return None
        except Exception:
            return None


# eBPF C program running in kernel space
EBPF_EXECVEAT_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// THE BRIDGE
BPF_HASH(blocked_pids, u32, u32);

struct exec_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall_type[16];
    u32 kernel_killed; // THE RECEIPT
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    struct exec_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    __builtin_memcpy(event.syscall_type, "execveat", 9);

    u32 *is_blocked = blocked_pids.lookup(&event.pid);
    if (is_blocked) {
        bpf_send_signal(9);
        event.kernel_killed = 1;
    } else {
        event.kernel_killed = 0;
    }

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

    u32 *is_blocked = blocked_pids.lookup(&event.pid);
    if (is_blocked) {
        bpf_send_signal(9);
        event.kernel_killed = 1;
    } else {
        event.kernel_killed = 0;
    }

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
        ("kernel_killed", ctypes.c_uint32),
    ]

class HidsEbpfExecutionMonitor(threading.Thread):
    def __init__(self, sha256_engine: HidsSha256Engine, yara_engine: HidsYaraEngine):
        super().__init__(daemon=True)
        self.engine = sha256_engine
        self.yara_engine = yara_engine
        self.running = True
        self.bpf = None
        # System paths protected by root permissions (Tier 2 skipped)
        self.safe_system_prefixes = (
            "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", 
            "/usr/libexec/", "/lib/", "/lib64/", "/bin/", "/sbin/"
        )

        # High-risk staging directories (Tier 2 Scanned)
        self.untrusted_execution_prefixes = (
            "/tmp", "/var/tmp", "/dev/shm", "/run/user", "/home", "/root"
        )

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

    def _enforce_kill_and_delete(self, pid, binary_path, engine_tier, signature_match, mitre_tag, syscall_used, process_name):
        action = "FAILED"
        try:
            os.kill(pid, signal.SIGKILL)
            action = "TERMINATED"
        except ProcessLookupError:
            action = "PROCESS_ALREADY_DEAD"
        except Exception as e:
            action = f"KILL_FAILED_{str(e)}"
            
        if action in ["TERMINATED", "PROCESS_ALREADY_DEAD"]:
            try:
                os.remove(binary_path)
                action = "TERMINATED_AND_DELETED"
            except FileNotFoundError:
                action = "TERMINATED_BUT_ALREADY_DELETED"
            except Exception:
                action = "TERMINATED_BUT_DELETE_FAILED"

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "engine_tier": engine_tier,
            "detection_context": "PROCESS_EXECUTION",
            "status": "CRITICAL",
            "pid": pid,
            "process_name": process_name,
            "binary_path": binary_path,
            "syscall": syscall_used,
            "signature_match": signature_match,
            "mitre_attack": mitre_tag,
            "action_taken": action
        }
        print(f"\n[!!!] MALICIOUS EXECUTION NEUTRALIZED [!!!]\n{json.dumps(alert, indent=4)}")

    def _handle_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(ExecEvent)).contents
        raw_filename = event.filename.decode("utf-8", errors="ignore").strip()
        syscall_used = event.syscall_type.decode("utf-8", errors="ignore").strip()
        comm = event.comm.decode("utf-8", errors="ignore").strip()

        if not raw_filename:
            return

        resolved_path = raw_filename
        if not os.path.isabs(resolved_path):
            try:
                resolved_path = os.readlink(f"/proc/{event.pid}/exe")
            except (OSError, FileNotFoundError):
                found_binary = shutil.which(resolved_path)
                if found_binary:
                    resolved_path = found_binary

        if event.kernel_killed == 1:
            action = "TERMINATED_IN_KERNEL_ONLY"
            if Path(resolved_path).is_file():
                try:
                    os.remove(resolved_path)
                    action = "TERMINATED_IN_KERNEL_AND_DELETED"
                except Exception:
                    pass

            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "engine_tier": "EBPF_KERNEL_ENFORCEMENT",
                "status": "CRITICAL",
                "pid": event.pid,
                "process_name": comm,
                "binary_path": resolved_path,
                "action_taken": action
            }
            print(f"\n[!!!] KERNEL-LEVEL KILL SUCCESSFUL [!!!]\n{json.dumps(alert, indent=4)}")
            return

        if Path(resolved_path).is_file():
            self._scan_execution(resolved_path, comm, event.pid, syscall_used)

    def _scan_execution(self, binary_path: str, comm: str, pid: int, syscall_used: str):
        try:
            file_hash = self.engine.calculate_sha256(binary_path)
            malware_name = self.engine.lookup_hash(file_hash)

            if malware_name:
                mitre_tag = map_mitre_attack("SHA256_SIGNATURE", "PROCESS_EXECUTION", malware_name)
                self._enforce_kill_and_delete(pid, binary_path, "SHA256_SIGNATURE", malware_name, mitre_tag, syscall_used, comm)
                return

            if binary_path.startswith(self.safe_system_prefixes):
                return

            if binary_path.startswith(self.untrusted_execution_prefixes):
                yara_match = self.yara_engine.scan_file(binary_path)
                if yara_match:
                    if not yara_match.startswith("[GENERIC]"):
                        mitre_tag = map_mitre_attack("YARA_HEURISTICS", "PROCESS_EXECUTION", yara_match)
                        self._enforce_kill_and_delete(pid, binary_path, "YARA_HEURISTICS", yara_match, mitre_tag, syscall_used, comm)
                        return
                    else:
                        mitre_tag = map_mitre_attack("YARA_HEURISTICS", "PROCESS_EXECUTION", yara_match)
                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            "engine_tier": "YARA_HEURISTICS",
                            "detection_context": "PROCESS_EXECUTION",
                            "status": "SUSPICIOUS",
                            "pid": pid,
                            "process_name": comm,
                            "binary_path": binary_path,
                            "syscall": syscall_used,
                            "signature_match": yara_match,
                            "mitre_attack": mitre_tag,
                            "action_taken": "LOGGED"
                        }
                        print(f"\n[!!!] SUSPICIOUS EXECUTION LOGGED (TIER 2) [!!!]\n{json.dumps(alert, indent=4)}")
        except Exception:
            pass

    def stop(self):
        self.running = False


class HidsHandler(FileSystemEventHandler):
    def __init__(self, sha256_engine: HidsSha256Engine, yara_engine: HidsYaraEngine):
        self.engine = sha256_engine
        self.yara_engine = yara_engine
        self.recent_events = {}
        # Ephemeral desktop rendering prefixes to ignore
        self.ephemeral_prefixes = (
            "/tmp/gdk-pixbuf-", "/tmp/glycin-", "/tmp/gnome-desktop-", 
            "/tmp/.org.chromium.", "/tmp/systemd-private-", "/var/tmp/systemd-private-"
        )

    def process_file(self, file_path: str):
        if not os.path.isfile(file_path):
            return

        if any(file_path.startswith(prefix) for prefix in self.ephemeral_prefixes):
            return

        # Discard 0-byte files to prevent creation race condition
        try:
            if os.path.getsize(file_path) == 0:
                return
        except OSError:
            return

        # Reduced debounce window to 0.1s
        current_time = time.time()
        if file_path in self.recent_events and (current_time - self.recent_events[file_path]) < 0.1:
            return
        self.recent_events[file_path] = current_time

        try:
            # Tier 1: SHA256 Signature Scan
            file_hash = self.engine.calculate_sha256(file_path)
            malware_name = self.engine.lookup_hash(file_hash)


            if malware_name:
                mitre_tag = map_mitre_attack("SHA256_SIGNATURE", "FILE_DROP", malware_name)

                action = "DETECTED"
                try:
                    os.remove(file_path)
                    action = "DELETED_FROM_DISK"
                except Exception:
                    action = "QUARANTINE_FAILED"

                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "engine_tier": "SHA256_SIGNATURE",
                    "detection_context": "FILE_DROP",
                    "status": "ALERT",
                    "file_path": str(Path(file_path).resolve()),
                    "calculated_hash": file_hash,
                    "signature_match": malware_name,
                    "mitre_attack": mitre_tag,
                    "action_taken": action,
                }
                print(f"\n[!!!] MALICIOUS FILE DROP DETECTED (TIER 1) [!!!]\n{json.dumps(alert, indent=4)}")
                return

            # Tier 2: YARA Heuristic Scan
            yara_match = self.yara_engine.scan_file(file_path)
            if yara_match:
                mitre_tag = map_mitre_attack("YARA_HEURISTICS", "FILE_DROP", yara_match)
                status_level = "SUSPICIOUS" if yara_match.startswith("[GENERIC]") else "ALERT"

                action = "LOGGED"
                if status_level == "ALERT":
                    try:
                        os.remove(file_path)
                        action = "DELETED_FROM_DISK"
                    except Exception:
                        action = "QUARANTINE_FAILED"

                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "engine_tier": "YARA_HEURISTICS",
                    "detection_context": "FILE_DROP",
                    "status": status_level,
                    "file_path": str(Path(file_path).resolve()),
                    "calculated_hash": file_hash,
                    "signature_match": yara_match,
                    "mitre_attack": mitre_tag,
                    "action_taken": action,
                }
                print(f"\n[!!!] MALICIOUS PATTERN DROP DETECTED (TIER 2) [!!!]\n{json.dumps(alert, indent=4)}")
                return

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
    # Resolve true user home directory when running via sudo
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        user_home = Path(f"/home/{sudo_user}")
    else:
        user_home = Path.home()

    watch_directories = [
        # --- Staging & Dropper Zones (World-Writable) ---
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        
        # --- User-Space Persistence & Drop Zones ---
        str(user_home / "Downloads"),
        str(user_home / ".ssh"),
        str(user_home / ".config/autostart"),
        str(user_home / ".config/systemd/user"),
        
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