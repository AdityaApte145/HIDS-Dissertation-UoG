import hashlib
import json
import os
import subprocess
import sqlite3
import time
import threading
import ctypes
import shutil
import signal
import sys
import pwd
import pickle
from datetime import datetime, timezone
from pathlib import Path
import psutil

import yara
import numpy as np
import torch
import torch.nn as nn
from bcc import BPF
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Added this lock globally to prevent LLVM Segfaults
bcc_compile_lock = threading.Lock()

# ML Constants & Paths
MODEL_PATH = os.path.join(BASE_DIR, "hids_autoencoder.pth")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
SIGNATURE_DB_PATH = os.path.join(BASE_DIR, "hids_signatures.db")
YARA_RULES_DIR = os.path.join(BASE_DIR, "yara_rules")

ANOMALY_THRESHOLD = 0.025
MONITORED_SYSCALLS = [
    0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 16, 20, 21, 22, 23, 39, 41, 
    42, 43, 44, 45, 49, 50, 56, 57, 59, 60, 62, 72, 78, 87, 101, 102, 105, 257, 322, 332
]

ALERT_LOG_PATH = "/tmp/hids_alerts.jsonl"

def record_alert(alert_dict: dict):
    """Appends alert to a JSON-Lines file for the SOC dashboard."""
    try:
        with open(ALERT_LOG_PATH, "a") as f:
            f.write(json.dumps(alert_dict) + "\n")
    except Exception:
        pass

def kill_entire_process_tree(pid: int) -> int:
    """
    Recursively terminates a process and all its child worker processes.
    Returns the total number of killed processes.
    """
    if pid <= 1:
        return 0
        
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        
        # Kill all children first (bottom-up)
        for child in children:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
                
        # Kill the parent
        parent.kill()
        
        return len(children) + 1
    except (psutil.NoSuchProcess, PermissionError, Exception):
        # Fallback to standard OS kill if psutil hits a permission wall
        try:
            os.kill(pid, signal.SIGKILL)
            return 1
        except Exception:
            return 0

def map_mitre_attack(engine_tier: str, detection_context: str, match_name: str) -> dict:
    match_lower = match_name.lower()
    
    # --- TIER 3: DYNAMIC ANOMALY TTPs ---
    if engine_tier == "BEHAVIORAL_ANOMALY":
        if detection_context == "ANOMALY_NETWORK_C2":
            return {
                "tactic": "Command and Control",
                "technique_id": "T1071 / T1571",
                "technique_name": "Application Layer Protocol / Non-Standard Port",
                "description": "Massive spike in socket(), connect(), or sendto() syscalls. Indicates the process is beaconing to a C2 server, exfiltrating data, or conducting a network port scan."
            }
        elif detection_context == "ANOMALY_FILE_IO":
            return {
                "tactic": "Impact / Collection",
                "technique_id": "T1486 / T1560",
                "technique_name": "Data Encrypted for Impact / Archive Collected Data",
                "description": "Abnormal volume of open(), read(), write(), and unlink() syscalls. Highly indicative of a ransomware encryption loop or a staging script packing files for exfiltration."
            }
        elif detection_context == "ANOMALY_EXECUTION":
            return {
                "tactic": "Execution / Privilege Escalation",
                "technique_id": "T1059 / T1548",
                "technique_name": "Command and Scripting Interpreter / Abuse Elevation Control",
                "description": "Anomalous rate of clone(), fork(), or execve() syscalls. Suggests aggressive spawning of child processes, shell execution, or privilege manipulation."
            }
        else: # Generic fallback
            return {
                "tactic": "Execution / Defense Evasion",
                "technique_id": "T1059 / T1055",
                "technique_name": "Command and Scripting Interpreter / Process Injection",
                "description": "Uncategorized systemic deviation from baseline syscalls indicating memory evasion or anomalous execution."
            }

    # --- TIER 1 & 2: STATIC/HEURISTIC TTPs ---
    if detection_context == "PROCESS_EXECUTION":
        mitre_data = {
            "tactic": "Execution",
            "technique_id": "T1204.002",
            "technique_name": "User Execution: Malicious File",
            "description": "An attempt was made to execute a binary whose hash matches a known malware family in the signature database."
        }
        if any(term in match_lower for term in ["sh", "bash", "script", "python"]):
            mitre_data = {
                "tactic": "Execution",
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell",
                "description": "Execution of a suspicious shell script matching known malicious heuristic patterns."
            }
    else:  # FILE_DROP
        mitre_data = {
            "tactic": "Defense Evasion",
            "technique_id": "T1027",
            "technique_name": "Obfuscated/Compromised Files or Information",
            "description": "A suspicious file was dropped onto the filesystem containing obfuscated or heuristically malicious patterns."
        }
    return mitre_data

class SyscallAutoencoder(nn.Module):
    def __init__(self, input_dim: int):
        super(SyscallAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 24), nn.ReLU(),
            nn.Linear(24, 12), nn.ReLU(),
            nn.Linear(12, 8)
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 12), nn.ReLU(),
            nn.Linear(12, 24), nn.ReLU(),
            nn.Linear(24, input_dim), nn.Sigmoid()
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))

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

    # Namespaces whose rules constitute weak evidence: they match structural,
    # encoding or capability artefacts (base64 alphabets, embedded URLs, packer
    # stubs, syscall capabilities) that are common in legitimate binaries.
    LOW_CONFIDENCE_NAMESPACES = (
        "utils_",           # base64, domain, ip, magic, url, suspicious_strings
        "crypto_",          # crypto constant tables
        "packers_",         # packing is not itself malicious
        "capabilities_",    # capability enumeration, not attribution
        "yara_generic_",    # generic_cryptors, generic_dumps
    )

    # Rule-name prefixes used by the upstream ruleset (Roth et al.) to denote
    # hunting rules rather than confirmed malware-family attribution.
    LOW_CONFIDENCE_RULE_PREFIXES = ("susp_", "gen_", "hunt_", "pua_", "anomaly_")

    def scan_file(self, file_path: str) -> str | None:
        if not self.rules:
            return None
        try:
            matches = self.rules.match(file_path, timeout=2)
            if not matches:
                return None

            for match in matches:
                ns = match.namespace.lower()
                r = match.rule.lower()
                if ns.startswith(self.LOW_CONFIDENCE_NAMESPACES):
                    continue
                if r.startswith(self.LOW_CONFIDENCE_RULE_PREFIXES):
                    continue
                if "generic" in r or "base64" in r:
                    continue
                return f"{match.namespace} -> {match.rule}"

            return f"[GENERIC] {matches[0].namespace} -> {matches[0].rule}"

        except yara.TimeoutError:
            return None
        except Exception:
            return None


# eBPF C program running in kernel space
EBPF_EXECUTION_PROBE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(ignored_pids, u32, u8);
BPF_HASH(blocked_pids, u32, u32);

struct exec_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char syscall_type[16];
    u32 kernel_killed;
    int fd;
};

BPF_PERF_OUTPUT(exec_events);

static __always_inline int process_exec(void *ctx, const char __user *filename,
                                        const char *sys_name, size_t sys_len, int fd) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (ignored_pids.lookup(&pid)) return 0; // SELF EXCLUSION

    struct exec_event_t event = {};
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid();
    event.fd = fd;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
    __builtin_memcpy(event.syscall_type, sys_name, sys_len);

    u32 *is_blocked = blocked_pids.lookup(&event.pid);
    if (is_blocked) {
        bpf_send_signal(9);
        event.kernel_killed = 1;
    } else {
        event.kernel_killed = 0;
    }
    exec_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) { return process_exec(args, args->filename, "execveat", 9, args->fd); }
TRACEPOINT_PROBE(syscalls, sys_enter_execve) { return process_exec(args, args->filename, "execve", 7, -1); }
"""

class ExecEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16), ("filename", ctypes.c_char * 256),
        ("syscall_type", ctypes.c_char * 16), ("kernel_killed", ctypes.c_uint32),
        ("fd", ctypes.c_int),
    ]

class HidsEbpfExecutionMonitor(threading.Thread):
    def __init__(self, sha256_engine, yara_engine, engine_pid):
        super().__init__(daemon=True)
        self.engine, self.yara_engine, self.engine_pid = sha256_engine, yara_engine, engine_pid
        self.running, self.bpf = True, None
        self.safe_system_prefixes = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/lib/", "/lib64/", "/bin/", "/sbin/")
        self.untrusted_execution_prefixes = ("/tmp", "/var/tmp", "/dev/shm", "/run/user", "/home", "/root")
        # Set to False to make fileless execution log-only instead of auto-terminate.
        self.kill_on_fileless = False

    def run(self):
        try:
            with bcc_compile_lock:
                self.bpf = BPF(text=EBPF_EXECUTION_PROBE)
                self.bpf["ignored_pids"][ctypes.c_uint32(self.engine_pid)] = ctypes.c_uint8(1)
            self.bpf["exec_events"].open_perf_buffer(self._handle_event)
            print("[+] [Tier 1/2] eBPF execution trap active (execve/execveat).")
        except Exception as e:
            print(f"[-] Failed to load eBPF execution probe: {e}")
            return

        while self.running:
            try: self.bpf.perf_buffer_poll(timeout=100)
            except Exception: break

    def _enforce_kill_and_delete(self, pid, binary_path, engine_tier, signature_match, mitre_tag, syscall_used, process_name):
        # --- Containment: terminate the process and all descendants ---
        killed_count = kill_entire_process_tree(pid)
        if killed_count > 0:
            kill_status = f"TERMINATED_TREE_({killed_count}_PROCESSES)"
        else:
            kill_status = "PROCESS_ALREADY_DEAD_OR_DENIED"

        # Register PID in the kernel blocklist so any re-exec attempt is
        # SIGKILLed in-kernel before the syscall completes.
        try:
            if self.bpf is not None:
                self.bpf["blocked_pids"][ctypes.c_uint32(pid)] = ctypes.c_uint32(1)
        except Exception:
            pass
        
        try:
            os.remove(binary_path)
            delete_status = "DELETED_FROM_DISK"
        except FileNotFoundError:
            delete_status = "ALREADY_ABSENT"
        except PermissionError:
            delete_status = "DELETE_DENIED"
        except Exception as e:
            delete_status = f"DELETE_FAILED_({type(e).__name__})"

        neutralized = killed_count > 0 and delete_status in ("DELETED_FROM_DISK", "ALREADY_ABSENT")

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "engine_tier": engine_tier, "status": "CRITICAL", "pid": pid,
            "process_name": process_name, "binary_path": binary_path, "syscall": syscall_used,
            "signature_match": signature_match, "mitre_attack": mitre_tag,
            "kill_status": kill_status, "delete_status": delete_status,
            "processes_killed": killed_count,
            "action_taken": f"{kill_status}+{delete_status}",
        }
        record_alert(alert)

        banner = "MALICIOUS EXECUTION NEUTRALIZED" if neutralized else "MALICIOUS EXECUTION - PARTIAL CONTAINMENT"
        print(f"\n[!!!] {banner} [!!!]\n{json.dumps(alert, indent=4)}")

    def _resolve_exec_path(self, pid: int, raw_filename: str) -> str | None:
        """
        Resolves the target of an exec to an absolute path.

        NOTE: at sys_enter the exec has not yet occurred, so /proc/PID/exe still
        points at the *calling* binary (usually the shell) and must never be used
        here. Relative paths are resolved against the caller's cwd instead.
        """
        if os.path.isabs(raw_filename):
            return raw_filename

        if "/" in raw_filename:                     # ./payload, ../bin/x, sub/dir/x
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
                return os.path.realpath(os.path.join(cwd, raw_filename))
            except OSError:
                return None

        return shutil.which(raw_filename)           # bare command -> PATH lookup

    def _handle_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(ExecEvent)).contents
        raw_filename = event.filename.decode("utf-8", errors="ignore").strip()
        syscall_used = event.syscall_type.decode("utf-8", errors="ignore").strip()
        comm = event.comm.decode("utf-8", errors="ignore").strip()


        if event.pid == self.engine_pid:
            return

        if not raw_filename:
            if event.fd >= 0:
                self._handle_fileless_execution(event.pid, event.fd, comm, syscall_used)
            return

        resolved_path = self._resolve_exec_path(event.pid, raw_filename)
        if not resolved_path:
            return

        # --- Already blocked in-kernel: remove the artefact and stop ---
        if event.kernel_killed == 1:
            try:
                os.remove(resolved_path)
            except Exception:
                pass
            return

        if Path(resolved_path).is_file():
            self._scan_execution(resolved_path, comm, event.pid, syscall_used)

    def _handle_fileless_execution(self, pid: int, fd: int, comm: str, syscall_used: str):
        """
        Handles anonymous in-memory execution. The payload never touches the
        filesystem, so Tier 1/2 cannot scan it; detection is based on the
        execution pattern itself rather than on content.
        """
        try:
            fd_target = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            fd_target = "<unresolvable>"

        anonymous = (
            fd_target.startswith("/memfd:")
            or fd_target.startswith("/dev/shm")
            or fd_target == "<unresolvable>"
            or "(deleted)" in fd_target
        )
        if not anonymous:
            return

        mitre_tag = {
            "tactic": "Defense Evasion",
            "technique_id": "T1620",
            "technique_name": "Reflective Code Loading",
            "description": ("Execution of an anonymous in-memory file descriptor via execveat with "
                            "AT_EMPTY_PATH. The payload has no on-disk representation, defeating "
                            "hash- and content-based scanning."),
        }

        if self.kill_on_fileless:
            killed_count = kill_entire_process_tree(pid)
            kill_status = (f"TERMINATED_TREE_({killed_count}_PROCESSES)"
                           if killed_count > 0 else "PROCESS_ALREADY_DEAD_OR_DENIED")
            action = "TERMINATED_FILELESS_PAYLOAD"
            status = "CRITICAL"
        else:
            kill_status = "NOT_ATTEMPTED_LOG_ONLY_MODE"
            action = "LOGGED_FOR_SOC_REVIEW"
            status = "WARNING"

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "engine_tier": "FILELESS_EXECUTION", "status": status, "pid": pid,
            "process_name": comm, "binary_path": fd_target, "syscall": syscall_used,
            "signature_match": "ANONYMOUS_MEMORY_EXECUTION", "mitre_attack": mitre_tag,
            "kill_status": kill_status,
            "delete_status": "NOT_APPLICABLE_NO_DISK_ARTEFACT",
            "action_taken": action,
        }
        record_alert(alert)
        print(f"\n[!!!] FILELESS EXECUTION DETECTED [!!!]\n{json.dumps(alert, indent=4)}")

    def _scan_execution(self, binary_path, comm, pid, syscall_used):
        try:
            if (malware_name := self.engine.lookup_hash(self.engine.calculate_sha256(binary_path))):
                self._enforce_kill_and_delete(pid, binary_path, "SHA256_SIGNATURE", malware_name, map_mitre_attack("SHA256_SIGNATURE", "PROCESS_EXECUTION", malware_name), syscall_used, comm)
                return
            if binary_path.startswith(self.safe_system_prefixes): return
            if binary_path.startswith(self.untrusted_execution_prefixes):
                if (yara_match := self.yara_engine.scan_file(binary_path)):
                    mitre_tag = map_mitre_attack("YARA_HEURISTICS", "PROCESS_EXECUTION", yara_match)
                    if not yara_match.startswith("[GENERIC]"):
                        self._enforce_kill_and_delete(pid, binary_path, "YARA_HEURISTICS", yara_match, mitre_tag, syscall_used, comm)
                    else:
                        print(f"\n[!] SUSPICIOUS EXECUTION LOGGED (TIER 2)\nPID: {pid} | {binary_path} | Match: {yara_match}")
        except Exception: pass

    def stop(self): self.running = False

EBPF_ANOMALY_PROBE = r"""
#include <uapi/linux/ptrace.h>
BPF_HASH(ignored_pids, u32, u8);
struct key_t { u32 pid; u32 syscall_id; };
BPF_HASH(syscall_counts, struct key_t, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0 || ignored_pids.lookup(&pid)) return 0; // SELF EXCLUSION

    struct key_t key = {.pid = pid, .syscall_id = args->id};
    u64 zero = 0, *val;
    val = syscall_counts.lookup_or_try_init(&key, &zero);
    if (val) (*val)++;
    return 0;
}
"""

class HidsAnomalyMonitor(threading.Thread):
    def __init__(self, engine_pid: int):
        super().__init__(daemon=True)
        self.engine_pid, self.running = engine_pid, True
        self.model, self.scaler, self.bpf = None, None, None

    def _get_process_metadata(self, pid: int) -> dict:
        meta = {"comm": "unknown", "exe": "unknown", "user": "unknown"}
        try:
            with open(f"/proc/{pid}/comm", "r") as f: meta["comm"] = f.read().strip()
            meta["exe"] = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        meta["user"] = pwd.getpwuid(int(line.split()[1])).pw_name
                        break
        except Exception: pass
        return meta

    def run(self):
        if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
            print("[-] [Tier 3] Model/Scaler missing. Anomaly engine disabled.")
            return

        self.model = SyscallAutoencoder(len(MONITORED_SYSCALLS))
        self.model.load_state_dict(torch.load(MODEL_PATH, weights_only=True))
        self.model.eval()
        with open(SCALER_PATH, "rb") as f: self.scaler = pickle.load(f)

        try:
            with bcc_compile_lock:
                self.bpf = BPF(text=EBPF_ANOMALY_PROBE)
                self.bpf["ignored_pids"][ctypes.c_uint32(self.engine_pid)] = ctypes.c_uint8(1)
            
            syscall_counts = self.bpf["syscall_counts"]
            print("[+] [Tier 3] eBPF Behavioral Anomaly Engine active.")
        except Exception as e:
            print(f"[-] Failed to load anomaly probe: {e}")
            return

        while self.running:
            time.sleep(1.0)
            pid_matrix = {}
            for k, v in syscall_counts.items():
                if k.pid != self.engine_pid:
                    pid_matrix.setdefault(k.pid, {})[k.syscall_id] = v.value
            syscall_counts.clear()

            for pid, syscalls in pid_matrix.items():
                input_arr = np.array([[syscalls.get(s, 0) for s in MONITORED_SYSCALLS]], dtype=np.float32)
                try:
                    tensor_in = torch.tensor(self.scaler.transform(input_arr), dtype=torch.float32)
                    with torch.no_grad():
                        loss = nn.MSELoss()(self.model(tensor_in), tensor_in).item()

                    if loss > ANOMALY_THRESHOLD:
                        meta = self._get_process_metadata(pid)
                        
                        # DYNAMIC TTP CLASSIFICATION
                        # Check which raw syscalls caused the anomaly spike
                        dynamic_context = "PROCESS_BEHAVIOR" # Default fallback
                        
                        # Check Network Syscalls (41=socket, 42=connect, 44=sendto, 45=recvfrom)
                        if sum(syscalls.get(s, 0) for s in [41, 42, 44, 45]) > 100:
                            dynamic_context = "ANOMALY_NETWORK_C2"
                            
                        # Check File I/O & Destruction (0=read, 1=write, 2=open, 87=unlink)
                        elif sum(syscalls.get(s, 0) for s in [0, 1, 2, 87]) > 500:
                            dynamic_context = "ANOMALY_FILE_IO"
                            
                        # Check Execution & Forking (56=clone, 57=fork, 59=execve)
                        elif sum(syscalls.get(s, 0) for s in [56, 57, 59]) > 20:
                            dynamic_context = "ANOMALY_EXECUTION"

                        mitre_tag = map_mitre_attack("BEHAVIORAL_ANOMALY", dynamic_context, meta["comm"])

                        alert = {
                            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            "engine_tier": "BEHAVIORAL_ANOMALY",
                            "status": "WARNING",
                            "pid": pid,
                            "process_name": meta["comm"],
                            "binary_path": meta["exe"],
                            "user": meta["user"],
                            "reconstruction_loss": round(loss, 5),
                            "action_taken": "LOGGED_FOR_SOC_REVIEW",
                            "remediation_hint": f"kill -9 {pid}",
                            "mitre_attack": mitre_tag
                        }
                        
                        # Log to file for SOC Dashboard
                        record_alert(alert)
                            
                        print(f"\n\033[93m[!] BEHAVIORAL ANOMALY DETECTED [!]\033[0m\n{json.dumps(alert, indent=4)}")
                except Exception: pass

    def stop(self): self.running = False

EBPF_ANTI_TAMPER_PROBE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(protected_pids, u32, u8);

struct tamper_event_t {
    u32 attacker_pid;
    u32 attacker_uid;
    u32 target_pid;
    int signal;
    u32 retaliated;
    char attacker_comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(tamper_events);

TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
    u32 target_pid = args->pid;
    int sig = args->sig;

    u8 *is_protected = protected_pids.lookup(&target_pid);
    if (!is_protected) return 0;

    u32 attacker_pid = bpf_get_current_pid_tgid() >> 32;
    if (attacker_pid == target_pid) return 0;   // ignore self-signalling

    struct tamper_event_t event = {};
    event.attacker_pid = attacker_pid;
    event.attacker_uid = bpf_get_current_uid_gid();
    event.target_pid = target_pid;
    event.signal = sig;
    bpf_get_current_comm(&event.attacker_comm, sizeof(event.attacker_comm));

    // Retaliate only against terminating signals. Non-terminating signals are
    // recorded but not acted upon.
    if (sig == 9 || sig == 15) {
        bpf_send_signal_thread(9);
        event.retaliated = 1;
    } else {
        event.retaliated = 0;
    }

    tamper_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


class TamperEvent(ctypes.Structure):
    _fields_ = [
        ("attacker_pid", ctypes.c_uint32),
        ("attacker_uid", ctypes.c_uint32),
        ("target_pid", ctypes.c_uint32),
        ("signal", ctypes.c_int),
        ("retaliated", ctypes.c_uint32),
        ("attacker_comm", ctypes.c_char * 16),
    ]

class HidsAntiTamper(threading.Thread):

    def __init__(self, engine_pid):
        super().__init__(daemon=True)
        self.engine_pid = engine_pid
        self.bpf = None
        self.running = True

    def _handle_tamper_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(TamperEvent)).contents
        comm = event.attacker_comm.decode("utf-8", errors="ignore").strip()

        try:
            user = pwd.getpwuid(event.attacker_uid).pw_name
        except (KeyError, Exception):
            user = str(event.attacker_uid)

        try:
            exe = os.readlink(f"/proc/{event.attacker_pid}/exe")
        except OSError:
            exe = "<exited>"

        try:
            with open(f"/proc/{event.attacker_pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
        except OSError:
            cmdline = "<unavailable>"

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "engine_tier": "ANTI_TAMPER",
            "status": "CRITICAL" if event.retaliated else "WARNING",
            "pid": event.attacker_pid,
            "process_name": comm,
            "binary_path": exe,
            "cmdline": cmdline,
            "user": user,
            "uid": event.attacker_uid,
            "syscall": "kill",
            "target_pid": event.target_pid,
            "signal_sent": event.signal,
            "signature_match": "AGENT_TERMINATION_ATTEMPT",
            "mitre_attack": {
                "tactic": "Defense Evasion",
                "technique_id": "T1562.001",
                "technique_name": "Impair Defenses: Disable or Modify Tools",
                "description": ("A process attempted to send a terminating signal to the monitoring "
                                "agent. The attempt was attributed and recorded prior to any "
                                "resulting agent shutdown."),
            },
            "action_taken": ("ATTACKER_TERMINATED_MUTUAL_KILL" if event.retaliated
                             else "RECORDED_NON_TERMINATING_SIGNAL"),
        }
        record_alert(alert)
        print(f"\n\033[91m[!!!] TAMPER ATTEMPT DETECTED [!!!]\033[0m\n{json.dumps(alert, indent=4)}")

    def run(self):
        try:
            with bcc_compile_lock:
                self.bpf = BPF(text=EBPF_ANTI_TAMPER_PROBE)
                # Register our own PID as protected
                self.bpf["protected_pids"][ctypes.c_uint32(self.engine_pid)] = ctypes.c_uint8(1)
            self.bpf["tamper_events"].open_perf_buffer(self._handle_tamper_event)
            print("[+] [Tier 0] eBPF Anti-Tamper (attribution + mutual termination) active.")
        except Exception as e:
            print(f"[-] Failed to load anti-tamper probe: {e}")
            return

        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception:
                break

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

        if "/.hids/" in file_path or file_path == "/tmp/hids_alerts.jsonl":
                    return
        
        if any(file_path.startswith(prefix) for prefix in self.ephemeral_prefixes):
            return

        # Discard 0-byte files to prevent creation race condition
        try:
            if os.path.getsize(file_path) == 0:
                return
        except OSError:
            return

        current_time = time.time()
        if file_path in self.recent_events and (current_time - self.recent_events[file_path]) < 0.5:
            return
        self.recent_events[file_path] = current_time

        if len(self.recent_events) > 5000:
            cutoff = current_time - 60
            self.recent_events = {k: v for k, v in self.recent_events.items() if v > cutoff}

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
                record_alert(alert)
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
                record_alert(alert)
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
    if os.geteuid() != 0:
        print("[!] Fatal: Run with sudo for eBPF.")
        sys.exit(1)

    engine_pid = os.getpid()
    print(f"[+] Initializing Unified Linux HIDS Agent (PID: {engine_pid})...")

    sha256_engine = HidsSha256Engine("hids_signatures.db")
    yara_engine = HidsYaraEngine("yara_rules")
    print(f"[*] Test signature injected. Hash: {sha256_engine.inject_test_signature()}")

    sudo_user = os.environ.get("SUDO_USER")
    user_home = Path(f"/home/{sudo_user}") if sudo_user and sudo_user != "root" else Path.home()

    watch_directories = [
        "/tmp", "/var/tmp", "/dev/shm",
        str(user_home / "Downloads"), str(user_home / ".ssh"),
        str(user_home / ".config/autostart"), str(user_home / ".config/systemd/user"),
        "/etc/cron.d", "/var/spool/cron", "/etc/systemd/system", "/usr/local/bin"
    ]

    handler = HidsHandler(sha256_engine, yara_engine)
    observers = []
    for d in watch_directories:
        try:
            os.makedirs(d, exist_ok=True)
            obs = Observer()
            obs.schedule(handler, path=d, recursive=True)
            obs.start()
            observers.append(obs)
        except Exception: pass

    exec_monitor = HidsEbpfExecutionMonitor(sha256_engine, yara_engine, engine_pid)
    exec_monitor.start()

    anti_tamper = HidsAntiTamper(engine_pid)
    anti_tamper.start()

    anomaly_monitor = HidsAnomalyMonitor(engine_pid)
    anomaly_monitor.start()

    print("\nAll HIDS Layers Active! Press Ctrl+C to stop.\n")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping Agent...")
        exec_monitor.stop()
        anomaly_monitor.stop()
        anti_tamper.stop() 
        for o in observers: o.stop()
        for o in observers: o.join()

if __name__ == "__main__":
    start_hids()