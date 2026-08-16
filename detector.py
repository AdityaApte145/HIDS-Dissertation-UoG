#!/usr/bin/env python3
import time
import os
import signal
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import MinMaxScaler
from bcc import BPF
import pickle

MODEL_PATH = "hids_autoencoder.pth"
SCALER_PATH = "scaler_min_max.npy"

MONITORED_SYSCALLS = [
    0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 16, 20, 21, 22, 23, 39, 41, 
    42, 43, 44, 45, 49, 50, 56, 57, 59, 60, 62, 72, 78, 87, 101, 102, 105, 257, 322, 332
]

# Must match the architecture used in train_model.py
class SyscallAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(SyscallAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 24),
            nn.ReLU(),
            nn.Linear(24, 12),
            nn.ReLU(),
            nn.Linear(12, 8)
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 12),
            nn.ReLU(),
            nn.Linear(12, 24),
            nn.ReLU(),
            nn.Linear(24, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

EBPF_DETECTOR_CODE = r"""
#include <uapi/linux/ptrace.h>

struct key_t {
    u32 pid;
    u32 syscall_id;
};

BPF_HASH(syscall_counts, struct key_t, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 sys_id = args->id;
    if (pid == 0) return 0;

    struct key_t key = {.pid = pid, .syscall_id = sys_id};
    u64 zero = 0, *val;
    val = syscall_counts.lookup_or_try_init(&key, &zero);
    if (val) {
        (*val)++;
    }
    return 0;
}
"""

def main():
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        print("[!] Model or scaler not found! Run train_model.py first.")
        return

    print("[+] Loading trained Autoencoder model...")
    input_dim = len(MONITORED_SYSCALLS)
    model = SyscallAutoencoder(input_dim)
    model.load_state_dict(torch.load(MODEL_PATH))
    model.eval()

    # Load the fitted scaler object using pickle
    import pickle
    SCALER_PICKLE = "scaler.pkl"
    if not os.path.exists(SCALER_PICKLE):
        print(f"[!] Scaler file '{SCALER_PICKLE}' not found. Update train_model.py to save it via pickle.")
        return
    with open(SCALER_PICKLE, "rb") as f:
        scaler = pickle.load(f)
    
    print("[+] Compiling eBPF live inference engine...")
    b = BPF(text=EBPF_DETECTOR_CODE)
    syscall_counts = b["syscall_counts"]

    # Define an anomaly threshold (Tune this based on normal loss values)
    ANOMALY_THRESHOLD = 0.05 

    print("[+] EDR Live Monitoring Active. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1.0)
            pid_matrix = {}

            for k, v in syscall_counts.items():
                if k.pid not in pid_matrix:
                    pid_matrix[k.pid] = {}
                pid_matrix[k.pid][k.syscall_id] = v.value

            syscall_counts.clear()

            if not pid_matrix:
                continue

            # Evaluate each active process
            for pid, syscalls in pid_matrix.items():
                # Skip system kernel threads or python itself if desired
                if pid == os.getpid():
                    continue

                feature_vector = [syscalls.get(s, 0) for s in MONITORED_SYSCALLS]
                input_arr = np.array([feature_vector], dtype=np.float32)
                
                # Normalize using training parameters
                input_scaled = scaler.transform(input_arr)
                tensor_in = torch.tensor(input_scaled, dtype=torch.float32)

                with torch.no_grad():
                    reconstruction = model(tensor_in)
                    loss = nn.MSELoss()(reconstruction, tensor_in).item()

                # Print live telemetry status
                if loss > ANOMALY_THRESHOLD:
                    print(f"\n[!] ALERT! Anomaly detected in PID {pid}! Reconstruction Error: {loss:.5f}")
                    
                    # TRIGGER SIGSTOP TRAP
                    try:
                        os.kill(pid, signal.SIGSTOP)
                        print(f"[🛡️] Process {pid} frozen via SIGSTOP.")
                        
                        choice = input(f"[?] Was this you running an approved task? (y/n): ").strip().lower()
                        if choice == 'y':
                            os.kill(pid, signal.SIGCONT)
                            print(f"[+] Process {pid} resumed.")
                        else:
                            os.kill(pid, signal.SIGKILL)
                            print(f"[x] Process {pid} terminated safely.")
                    except ProcessLookupError:
                        pass
                else:
                    print(f"[*] PID {pid} Normal (Loss: {loss:.4f})", end="\r")

    except KeyboardInterrupt:
        print("\n[+] Live monitor stopped.")

if __name__ == "__main__":
    main()
