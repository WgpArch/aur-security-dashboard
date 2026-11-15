#!/usr/bin/env python3
"""PAM Bait Daemon - Forensic-grade authentication honeypot."""
import os, json, time, datetime, subprocess, threading
from pathlib import Path

CONFIG_DIR = Path("/var/lib/pam-bait")
LOG_DIR = CONFIG_DIR / "logs"
FIFO_PATH = CONFIG_DIR / "pam_bait.fifo"

def setup():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not FIFO_PATH.exists():
        os.mkfifo(FIFO_PATH)

def generate_sarif(events, source):
    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "PAM-Bait", "version": "1.0.0"}},
            "results": [{"message": {"text": f"PAM Bait Triggered: {e.get('user', 'unknown')}@{e.get('service', 'unknown')}"},
                        "level": "error",
                        "ruleId": "PAM-BAIT-001"} for e in events]
        }]
    }, indent=2)

def process_auth_event(event_data):
    timestamp = datetime.datetime.now().isoformat()
    log_entry = {"timestamp": timestamp, **event_data}

    log_file = LOG_DIR / f"bait_{datetime.date.today()}.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    sarif_file = LOG_DIR / f"sarif_{timestamp.replace(':', '-')}.sarif"
    try:
        with open(sarif_file, "w") as f:
            f.write(generate_sarif([log_entry], "pam-bait"))
    except Exception as e:
        print(f"SARIF generation failed: {e}")

    subprocess.run(["notify-send", "-u", "critical",
                    "🚨 PAM BAIT TRIGGERED",
                    f"{event_data.get('user', 'unknown')}@{event_data.get('service', 'unknown')}"],
                   check=False)

def monitor_fifo():
    while True:
        try:
            with open(FIFO_PATH, "r") as fifo:
                for line in fifo:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            threading.Thread(target=process_auth_event, args=(event,), daemon=True).start()
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            print(f"FIFO monitor error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    setup()
    monitor_fifo()
