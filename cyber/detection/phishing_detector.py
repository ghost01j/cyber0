import re
import logging
import time
from urllib.parse import urlparse
from colorama import Fore, init

init(autoreset=True)

# ---------------- CONFIG ----------------
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "verify",
    "account", "bank", "paypal", "confirm"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".gq", ".ru"
]

PHISHING_SCORE_THRESHOLD = 60

logging.basicConfig(
    filename="phishing_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


# ---------------- LOGGING ----------------
def log_event(event):
    logging.info(str(event))


# ---------------- CORE DETECTION ----------------
def analyze_phishing(url, html_content=None):

    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    print(Fore.CYAN + f"[SCAN] Checking URL: {url}")

    # 1️⃣ Suspicious Keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 10

    # 2️⃣ Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20

    # 3️⃣ Long URL
    if len(url) > 75:
        score += 10

    # 4️⃣ IP based URL
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 25

    # 5️⃣ HTML Form Detection
    if html_content:
        html_lower = html_content.lower()

        if "<form" in html_lower:
            score += 20

        if "action=\"http" in html_lower:
            score += 15

    # ---------------- DECISION ----------------
    if score >= PHISHING_SCORE_THRESHOLD:

        alert = {
            "alert": "PHISHING_DETECTED",
            "url": url,
            "score": score,
            "timestamp": time.time()
        }

        print(Fore.RED + f"[ALERT] Phishing Detected! Score: {score}")
        log_event(alert)
        auto_quarantine(url)

    else:
        print(Fore.GREEN + f"[SAFE] URL appears safe. Score: {score}")


# ---------------- AUTO RESPONSE ----------------
def auto_quarantine(url):
    print(Fore.YELLOW + f"[ACTION] URL quarantined: {url}")
    # Example future actions:
    # Add to blacklist
    # Notify admin
    # Block via firewall


# ---------------- WRAPPER (REQUIRED FOR MAIN ENGINE) ----------------
def run_phishing_module(url, html=None):
    analyze_phishing(url, html)


# ---------------- STANDALONE TEST ----------------
if __name__ == "__main__":

    print("=== PHISHING DETECTOR TEST MODE ===")

    test_url = "http://g00gle-secure-account-update.xyz/login"

    fake_html = """
    <html>
        <body>
            <form action="http://evil-server.com">
                <input type="text">
                <input type="password">
            </form>
        </body>
    </html>
    """

    analyze_phishing(test_url, fake_html)