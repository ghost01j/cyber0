import time
import json
import logging
from collections import defaultdict
from colorama import Fore, init

init(autoreset=True)

# ---------------- CONFIG ----------------
VPN_SCORE_LIMIT = 50

SUSPICIOUS_IP_PREFIXES = [
    "185.", "103.", "198.", "172."
]

KNOWN_HOSTING_KEYWORDS = [
    "digitalocean", "amazon", "aws",
    "google", "microsoft", "vultr", "ovh"
]

KNOWN_TOR_EXIT_NODES = {
    "185.220.101.1",
    "51.68.172.45"
}

# Track user IP switching behavior
user_ip_history = defaultdict(list)

logging.basicConfig(
    filename="vpn_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------- LOGGING ----------------
def log_event(event):
    logging.info(json.dumps(event))


# ---------------- VPN DETECTION ENGINE ----------------
def analyze_vpn_activity(event):

    ip = event.get("ip")
    username = event.get("username")
    timestamp = event.get("timestamp")

    if not ip or not username or timestamp is None:
        return

    score = 0

    print(Fore.CYAN + f"[SCAN] Checking VPN usage from {ip}")

    # 1️⃣ Suspicious IP Prefix
    if any(ip.startswith(prefix) for prefix in SUSPICIOUS_IP_PREFIXES):
        score += 20

    # 2️⃣ Known TOR Exit Node
    if ip in KNOWN_TOR_EXIT_NODES:
        score += 40

    # 3️⃣ Hosting Provider Simulation (based on fake org field)
    org = event.get("org", "").lower()
    if any(keyword in org for keyword in KNOWN_HOSTING_KEYWORDS):
        score += 30

    # 4️⃣ Rapid IP Switching Detection
    user_ip_history[username].append((ip, timestamp))

    recent_ips = [
        entry for entry in user_ip_history[username]
        if timestamp - entry[1] <= 300
    ]

    unique_ips = len(set(ip for ip, _ in recent_ips))

    if unique_ips > 3:
        score += 25

    # ---------------- DECISION ----------------
    if score >= VPN_SCORE_LIMIT:

        alert = {
            "alert": "VPN_OR_PROXY_DETECTED",
            "ip": ip,
            "username": username,
            "score": score,
            "timestamp": timestamp
        }

        print(Fore.RED + f"[ALERT] VPN/Proxy detected for user {username}")
        log_event(alert)
        auto_response(ip)

    else:
        print(Fore.GREEN + f"[SAFE] No VPN risk detected | Score: {score}")


# ---------------- RESPONSE HOOK ----------------
def auto_response(ip):
    print(Fore.YELLOW + f"[ACTION] Logging VPN usage: {ip}")
    # Example:
    # Block IP
    # Force MFA
    # Notify SOC team


# ---------------- WRAPPER ----------------
def run_vpn_module(event):
    analyze_vpn_activity(event)


# ---------------- STANDALONE TEST ----------------
if __name__ == "__main__":

    print("=== VPN DETECTOR TEST MODE ===")

    test_event = {
        "ip": "185.220.101.1",
        "username": "admin",
        "timestamp": time.time(),
        "org": "Amazon AWS"
    }

    analyze_vpn_activity(test_event)