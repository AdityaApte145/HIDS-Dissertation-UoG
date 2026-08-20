#!/usr/bin/env python3
import curses
import json
import os
import signal
import sys
import time
import psutil
from datetime import datetime

ALERT_LOG_PATH = "/tmp/hids_alerts.jsonl"

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
        
        for child in children:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
                
        parent.kill()
        return len(children) + 1
    except (psutil.NoSuchProcess, PermissionError, Exception):
        try:
            os.kill(pid, signal.SIGKILL)
            return 1
        except Exception:
            return 0

class SocDashboard:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.alerts = []
        self.selected_idx = 0
        self.status_message = "Ready. Use UP/DOWN to navigate, 'k' to kill PID, 'i' to inspect, 'q' to quit."
        self.last_file_pos = 0

        # Setup curses
        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)     # Critical / Alert
        curses.init_pair(2, curses.COLOR_YELLOW, -1)  # Warning / Suspicious
        curses.init_pair(3, curses.COLOR_GREEN, -1)   # Normal / Active
        curses.init_pair(4, curses.COLOR_CYAN, -1)    # Headers & Borders
        curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_WHITE) # Selected row

        self.stdscr.nodelay(True)  # Non-blocking input

    def load_new_alerts(self):
        """Reads newly appended alerts from the JSONL log file."""
        if not os.path.exists(ALERT_LOG_PATH):
            return

        try:
            with open(ALERT_LOG_PATH, "r") as f:
                f.seek(self.last_file_pos)
                lines = f.readlines()
                self.last_file_pos = f.tell()

            for line in lines:
                line = line.strip()
                if line:
                    try:
                        alert = json.loads(line)
                        self.alerts.append(alert)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            self.status_message = f"Error reading alerts: {e}"

    def kill_process(self, pid: int):
        """Recursively terminates the selected process tree via dashboard keypress."""
        if pid <= 1:
            self.status_message = f"Refused to kill system PID {pid}!"
            return

        try:
            killed_count = kill_entire_process_tree(pid)
            if killed_count > 0:
                self.status_message = f"Successfully terminated process tree for PID {pid} ({killed_count} processes killed)."
            else:
                self.status_message = f"PID {pid} is already dead or could not be killed."
        except Exception as e:
            self.status_message = f"Failed to kill process tree for PID {pid}: {e}"

    def inspect_alert(self, alert: dict):
        """Displays full JSON and MITRE details in a pop-up overlay."""
        self.stdscr.nodelay(False)  # Wait for user input
        h, w = self.stdscr.getmaxyx()
        
        box_h = min(22, h - 4)
        box_w = min(80, w - 6)
        start_y = max(1, (h - box_h) // 2)
        start_x = max(1, (w - box_w) // 2)

        win = curses.newwin(box_h, box_w, start_y, start_x)
        win.box()
        win.attron(curses.color_pair(4) | curses.A_BOLD)
        win.addstr(0, 2, " [ ALERT DETAILS & MITRE TAXONOMY ] ")
        win.attroff(curses.color_pair(4) | curses.A_BOLD)

        lines = json.dumps(alert, indent=2).split("\n")
        for idx, line in enumerate(lines[:box_h - 4]):
            win.addstr(idx + 2, 2, line[:box_w - 4])

        win.addstr(box_h - 2, 2, "Press any key to close...", curses.A_DIM)
        win.refresh()
        win.getch()
        self.stdscr.nodelay(True)

    def draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()

        # 1. Header
        title = " === LINUX eBPF HIDS / SOC ANALYST CONSOLE === "
        self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
        self.stdscr.addstr(0, max(0, (w - len(title)) // 2), title[:w - 1])
        self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)

        # 2. Table Column Headers
        col_header = f"{'TIME':<10} | {'TIER':<18} | {'STATUS':<10} | {'PID':<7} | {'PROCESS / FILE':<24} | {'DETAILS':<20}"
        self.stdscr.attron(curses.A_UNDERLINE | curses.A_BOLD)
        self.stdscr.addstr(2, 2, col_header[:w - 4])
        self.stdscr.attroff(curses.A_UNDERLINE | curses.A_BOLD)

        # 3. Table Rows
        visible_rows = h - 6
        if self.alerts:
            # Keep selected index in bounds
            self.selected_idx = max(0, min(self.selected_idx, len(self.alerts) - 1))
            
            # Compute sliding view window
            start_row = max(0, self.selected_idx - (visible_rows // 2))
            end_row = min(len(self.alerts), start_row + visible_rows)

            for i in range(start_row, end_row):
                alert = self.alerts[i]
                y = 3 + (i - start_row)

                raw_ts = alert.get("timestamp", "").split("T")[-1].replace("Z", "")[:8]
                tier = alert.get("engine_tier", "UNKNOWN")[:18]
                status = alert.get("status", "INFO")[:10]
                pid = str(alert.get("pid", "N/A"))[:7]
                proc = str(alert.get("process_name") or alert.get("file_path", "unknown")).split("/")[-1][:24]
                
                details = ""
                if "signature_match" in alert:
                    details = str(alert["signature_match"])[:20]
                elif "reconstruction_loss" in alert:
                    details = f"Loss: {alert['reconstruction_loss']}"
                elif "action_taken" in alert:
                    details = alert["action_taken"][:20]

                row_str = f"{raw_ts:<10} | {tier:<18} | {status:<10} | {pid:<7} | {proc:<24} | {details:<20}"

                color = curses.color_pair(3)
                if status in ["CRITICAL", "ALERT"]:
                    color = curses.color_pair(1) | curses.A_BOLD
                elif status in ["WARNING", "SUSPICIOUS"]:
                    color = curses.color_pair(2)

                if i == self.selected_idx:
                    self.stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
                    self.stdscr.addstr(y, 2, row_str[:w - 4])
                    self.stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
                else:
                    self.stdscr.attron(color)
                    self.stdscr.addstr(y, 2, row_str[:w - 4])
                    self.stdscr.attroff(color)
        else:
            self.stdscr.addstr(4, 4, "[*] Waiting for live HIDS alerts... No threats detected yet.", curses.A_DIM)

        # 4. Footer & Status Bar
        footer = " [K] Kill Selected PID | [I] Inspect Details | [C] Clear | [Q] Quit "
        self.stdscr.attron(curses.color_pair(4))
        self.stdscr.addstr(h - 2, 2, footer[:w - 4])
        self.stdscr.attroff(curses.color_pair(4))

        self.stdscr.addstr(h - 1, 2, f"Status: {self.status_message}"[:w - 4], curses.A_BOLD)
        self.stdscr.refresh()

    def run(self):
        while True:
            self.load_new_alerts()
            self.draw()

            try:
                ch = self.stdscr.getch()
            except Exception:
                ch = -1

            if ch == ord('q') or ch == ord('Q'):
                break
            elif ch == curses.KEY_UP or ch == ord('w'):
                if self.selected_idx > 0:
                    self.selected_idx -= 1
            elif ch == curses.KEY_DOWN or ch == ord('s'):
                if self.selected_idx < len(self.alerts) - 1:
                    self.selected_idx += 1
            elif ch == ord('k') or ch == ord('K'):
                if self.alerts and 0 <= self.selected_idx < len(self.alerts):
                    target_pid = self.alerts[self.selected_idx].get("pid")
                    if isinstance(target_pid, int):
                        self.kill_process(target_pid)
                    else:
                        self.status_message = "Selected alert does not have an active process PID."
            elif ch == ord('i') or ch == ord('I'):
                if self.alerts and 0 <= self.selected_idx < len(self.alerts):
                    self.inspect_alert(self.alerts[self.selected_idx])
            elif ch == ord('c') or ch == ord('C'):
                self.alerts.clear()
                self.selected_idx = 0
                self.status_message = "Alert view cleared."

            time.sleep(0.05)


def main():
    if os.geteuid() != 0:
        print("[!] Warning: Run dashboard with sudo so you have permissions to send SIGKILL to flagged processes.")
        time.sleep(1)
    curses.wrapper(lambda stdscr: SocDashboard(stdscr).run())


if __name__ == "__main__":
    main()