import time
import json
import logging
from collections import defaultdict
from colorama import Fore, init

init(autoreset=True)

# ---------------- CONFIG ----------------
TIME_WINDOW = 60                 # seconds
PORT_THRESHOLD = 15              # ports scanned in time window
IP_THRESHOLD = 10                # total scan attempts
SCORE_LIMIT = 50

logging.basicConfig(
    filename="port_scan_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------- STORAGE ----------------
scan_data = defaultdict(lambda: {
    "ports": set(),
    "timestamps": [],
    "score": 0
})


# ---------------- LOGGING ----------------
def log_event(event):
    logging.info(json.dumps(event))


# ---------------- DETECTION ENGINE ----------------
def analyze_connection(event):

    ip = event.get("ip")
    port = event.get("port")
    timestamp = event.get("timestamp")

    if not ip or not port or not timestamp:
        return

    entry = scan_data[ip]

    entry["ports"].add(port)
    entry["timestamps"].append(timestamp)
    entry["score"] += 5

    # Remove old attempts outside time window
    entry["timestamps"] = [
        t for t in entry["timestamps"]
        if timestamp - t <= TIME_WINDOW
    ]

    # Detection logic
    vertical_scan = len(entry["ports"]) > PORT_THRESHOLD
    rapid_scan = len(entry["timestamps"]) > IP_THRESHOLD
    high_score = entry["score"] > SCORE_LIMIT

    if any([vertical_scan, rapid_scan, high_score]):

        alert = {
            "alert": "PORT_SCAN_DETECTED",
            "ip": ip,
            "unique_ports": len(entry["ports"]),
            "scan_attempts": len(entry["timestamps"]),
            "score": entry["score"],
            "timestamp": timestamp
        }

        print(Fore.RED + f"[ALERT] Port scan detected from {ip}")
        log_event(alert)

        # Reset tracking
        scan_data[ip] = {
            "ports": set(),
            "timestamps": [],
            "score": 0
        }


# ---------------- WRAPPER ----------------
def run_port_scan_module(event=None):

    # If called from main engine with event
    if event:
        analyze_connection(event)

    else:
        print(Fore.YELLOW + "[INFO] Port scan monitor running... (manual mode)")


# ---------------- STANDALONE TEST ----------------
if __name__ == "__main__":

    print("=== PORT SCAN DETECTOR TEST MODE ===")

    test_ip = "192.168.1.5"

    for p in range(1, 30):
        test_event = {
            "ip": test_ip,
            "port": p,
            "timestamp": time.time()
        }

        analyze_connection(test_event)