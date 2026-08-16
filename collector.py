#!/usr/bin/env python3
import time
import csv
import os
import ctypes
from bcc import BPF

# Top 40 monitored Linux x86_64 system calls
MONITORED_SYSCALLS = [
    0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 16, 20, 21, 22, 23, 39, 41, 
    42, 43, 44, 45, 49, 50, 56, 57, 59, 60, 62, 72, 78, 87, 101, 102, 105, 257, 322, 332
]

OUTPUT_CSV = "normal_syscall_traffic.csv"
SAMPLING_INTERVAL = 1.0

EBPF_COLLECTOR_CODE = r"""
#include <uapi/linux/ptrace.h>

struct key_t {
    u32 pid;
    u32 syscall_id;
};

BPF_HASH(syscall_counts, struct key_t, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 sys_id = args->id;

    if (pid == 0) return 0; // Ignore kernel idle tasks

    struct key_t key = {.pid = pid, .syscall_id = sys_id};
    u64 zero = 0, *val;
    val = syscall_counts.lookup_or_try_init(&key, &zero);
    if (val) {
        (*val)++;
    }
    return 0;
}
"""

def init_csv():
    if not os.path.exists(OUTPUT_CSV):
        headers = ["timestamp", "pid"] + [f"sys_{s}" for s in MONITORED_SYSCALLS]
        with open(OUTPUT_CSV, mode="w", newline="") as f:
            csv.writer(f).writerow(headers)

def main():
    print("[+] Compiling eBPF Syscall Matrix Collector...")
    b = BPF(text=EBPF_COLLECTOR_CODE)
    syscall_counts = b["syscall_counts"]

    init_csv()
    print(f"[+] Recording system telemetry to '{OUTPUT_CSV}'.")

    sample_count = 0
    try:
        while True:
            time.sleep(SAMPLING_INTERVAL)
            current_time = int(time.time())
            pid_matrix = {}

            for k, v in syscall_counts.items():
                if k.pid not in pid_matrix:
                    pid_matrix[k.pid] = {}
                pid_matrix[k.pid][k.syscall_id] = v.value

            syscall_counts.clear()

            if pid_matrix:
                with open(OUTPUT_CSV, mode="a", newline="") as f:
                    writer = csv.writer(f)
                    for pid, syscalls in pid_matrix.items():
                        feature_row = [current_time, pid]
                        for sys_id in MONITORED_SYSCALLS:
                            feature_row.append(syscalls.get(sys_id, 0))
                        writer.writerow(feature_row)
                        sample_count += 1

                print(f"[*] Harvested {len(pid_matrix)} active PIDs (Total records: {sample_count})", end="\r")

    except KeyboardInterrupt:
        print(f"\n[+] Telemetry collection stopped. Total samples: {sample_count}")

if __name__ == "__main__":
    main()