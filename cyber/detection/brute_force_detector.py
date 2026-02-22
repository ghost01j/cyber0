import time
import json
import logging
from collections import defaultdict
from colorama import Fore, init

init(autoreset=True)

# ---------------- CONFIG ----------------
TIME_WINDOW = 120              # seconds
FAIL_THRESHOLD = 10            # failures per IP
USER_TARGET_THRESHOLD = 5      # unique usernames per IP
DISTRIBUTED_THRESHOLD = 5      # unique IPs per user
SUSPICION_SCORE_LIMIT = 50     # risk score threshold

# ---------------- STORAGE ----------------
ip_data = defaultdict(lambda: {
    "failures": [],
    "usernames": set(),
    "score": 0
})

user_data = defaultdict(lambda: {
    "ips": set(),
    "failures": []
})

logging.basicConfig(
    filename="advanced_bruteforce.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------- LOGGING ----------------
def log_event(event):
    logging.info(json.dumps(event))


# ---------------- DETECTION ENGINE ----------------
def analyze_login_attempt(event):

    ip = event.get("ip")
    username = event.get("username")
    success = event.get("success")
    current_time = event.get("timestamp")

    # Validation
    if not ip or not username or current_time is None:
        return

    # Only track failed logins
    if success:
        return

    ip_entry = ip_data[ip]
    user_entry = user_data[username]

    # Update IP tracking
    ip_entry["failures"].append(current_time)
    ip_entry["usernames"].add(username)
    ip_entry["score"] += 5

    # Update user tracking
    user_entry["ips"].add(ip)
    user_entry["failures"].append(current_time)

    # Remove old attempts outside time window
    ip_entry["failures"] = [
        t for t in ip_entry["failures"]
        if current_time - t <= TIME_WINDOW
    ]

    user_entry["failures"] = [
        t for t in user_entry["failures"]
        if current_time - t <= TIME_WINDOW
    ]

    # Detection logic
    too_many_failures = len(ip_entry["failures"]) > FAIL_THRESHOLD
    password_spray = len(ip_entry["usernames"]) > USER_TARGET_THRESHOLD
    distributed_attack = len(user_entry["ips"]) > DISTRIBUTED_THRESHOLD
    high_score = ip_entry["score"] > SUSPICION_SCORE_LIMIT

    if any([too_many_failures, password_spray, distributed_attack, high_score]):

        alert = {
            "alert": "BRUTE_FORCE_DETECTED",
            "ip": ip,
            "username": username,
            "failures": len(ip_entry["failures"]),
            "unique_usernames": len(ip_entry["usernames"]),
            "unique_ips_on_user": len(user_entry["ips"]),
            "score": ip_entry["score"],
            "timestamp": current_time
        }

        print(Fore.RED + f"[ALERT] Brute Force Detected from {ip}")
        log_event(alert)

        # Reset attacker tracking
        ip_data[ip] = {
            "failures": [],
            "usernames": set(),
            "score": 0
        }


# ---------------- WRAPPER (Required for main engine) ----------------
def run_bruteforce_module(event):
    analyze_login_attempt(event)


# ---------------- STANDALONE TEST ----------------
if __name__ == "__main__":
    print("=== BRUTE FORCE DETECTOR TEST MODE ===")

    test_event = {
        "ip": "192.168.1.10",
        "username": "admin",
        "success": False,
        "timestamp": time.time()
    }

    for _ in range(15):
        analyze_login_attempt(test_event)