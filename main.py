import psutil
import time
import datetime
from colorama import init, Fore, Style
from win10toast import ToastNotifier
import os
import sys

if getattr(sys, 'frozen', False):
    exe_dir = os.path.dirname(sys.executable)
else:
    exe_dir = os.path.dirname(os.path.abspath(__file__))

log_file_path = os.path.join(exe_dir, "keylogger.txt")

# Initialize colorama
init(autoreset=True)
toaster = ToastNotifier()

# Suspicious keywords list
SUSPICIOUS_KEYWORDS = {"keylogger", "hook", "logger", "stealer", "spy",
    "inject", "sniffer", "capture", "exploit", "ransom",
    "malware", "backdoor", "reverse_shell", "persistence",
    "spyware", "infostealer", "keycapture", "record_keys",
    "payload", "shellcode", "trojan", "clipbanker",
    "screenshot", "clipboard", "pynput", "keyboard", "key_event",
    "botnet", "remote_access", "ransomware", "exe_hidden"}

# 📊 Summary counters
total_scans = 0
total_suspicious_found = 0
total_processes_killed = 0
last_scan_time = None
last_summary_time = time.time()

SUMMARY_INTERVAL = 86400 #24 hours = 86400 sec


def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #print(f"writing to log file at:{log_file_path}")
    with open(log_file_path, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def monitor_processes():
    global total_scans, total_suspicious_found, total_processes_killed, last_scan_time, last_summary_time
    print(Fore.CYAN + "🔍 Starting Keylogger Detection & Auto-Blocker...")

    while True:
        if os.path.exists(os.path.join(exe_dir, "stop.txt")):
            toaster.show_toast(
                "Keylogger Detection Stopped",
                "Stopped by stop.txt file",
                duration=10
            )
            print(Fore.MAGENTA + "\n\n[STOP] stop.txt file found. Stopping program....")
            log_event("[STOP] Program stopped by stop.txt file.")
            break
        
        found_suspicious = False
        total_scans += 1
        last_scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pname = proc.info['name'].lower()
                for word in SUSPICIOUS_KEYWORDS:
                    if word in pname:
                        alert_msg = f"[ALERT] Suspicious process found: {pname} (PID: {proc.info['pid']})"
                        print(Fore.RED + alert_msg)
                        log_event(alert_msg)

                        #window notification
                        toaster.show_toast(
                            "Suspicious Process Detected!",
                            f"{pname} (PID: {proc.info['pid']})",
                            duration=5
                        )
                    
                        # Kill process
                        proc.kill()
                        kill_msg = f"Killed process: {pname} (PID: {proc.info['pid']})"
                        print(Fore.YELLOW + kill_msg)
                        log_event(kill_msg)

                        total_suspicious_found += 1
                        total_processes_killed += 1
                        found_suspicious = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not found_suspicious:
            safe_msg = "[INFO] No suspicious process found at this scan"
            print(Fore.GREEN + safe_msg)
            log_event(safe_msg)

        if time.time() - last_summary_time >= SUMMARY_INTERVAL:
            toaster.show_toast(
                "Daily Security Summary",
                f"Scans: {total_scans} | Suspicious: {total_suspicious_found} | Killed: {total_processes_killed}",
                duration=10
                
            )
            last_summary_time = time.time()

        time.sleep(10)  # Repeat every 5 seconds

if __name__ == "__main__":
    try:
        monitor_processes()
    except KeyboardInterrupt:
        # 📊 Print summary on Ctrl+C
        print(Fore.MAGENTA + "\n\n🔍 Scan Summary Report")
        print(Fore.MAGENTA + "-"*35)
        print(Fore.MAGENTA + f"✅ Total scans performed : {total_scans}")
        print(Fore.MAGENTA + f"🚨 Total suspicious found : {total_suspicious_found}")
        print(Fore.MAGENTA + f"💥 Total processes killed : {total_processes_killed}")
        print(Fore.MAGENTA + f"⏰ Last scan time : {last_scan_time}")
        print(Fore.MAGENTA + "-"*35)
        print(Fore.MAGENTA + "👋 Program stopped by user.")

        #show notificaton on stop
        toaster.show_toast(
            "Keylogger Detection Stopped",
            "Program has been stopped by user.",
            duration=10
        )
