import time
import threading

from detection.anomaly_ai_detector import run_anomaly_module
from detection.brute_force_detector import run_bruteforce_module
from detection.vpn_detector import run_vpn_module
from detection.phishing_detector import run_phishing_module
from detection.malware_detector import run_malware_module
from detection.port_scan_detector import run_port_scan_module


def event_router(event):

    event_type = event.get("type")
    print(f"\n[ENGINE] Processing {event_type} event...\n")

    if event_type == "login":
        run_bruteforce_module(event)
        run_vpn_module(event)
        run_anomaly_module(event)

    elif event_type == "network":
        run_anomaly_module(event)

    elif event_type == "file":
        run_malware_module(event["path"])

    elif event_type == "url":
        run_phishing_module(event["url"], event.get("html"))

    elif event_type == "port_monitor":
        threading.Thread(target=run_port_scan_module).start()

    else:
        print("[ENGINE] Unknown event type")


if __name__ == "__main__":

    print("=== UNIFIED CYBER DEFENSE ENGINE STARTED ===")

    login_event = {
        "type": "login",
        "ip": "185.220.101.1",
        "username": "admin",
        "success": False,
        "timestamp": time.time(),
        "failed_logins": 25,
        "requests_per_minute": 300,
        "data_transfer_kb": 1500
    }

    event_router(login_event)