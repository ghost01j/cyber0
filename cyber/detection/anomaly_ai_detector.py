import os
import time
import json
import joblib
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from colorama import Fore, init

init(autoreset=True)

# ---------------- CONFIG ----------------
MODEL_PATH = "models/anomaly_model.pkl"
ANOMALY_THRESHOLD = -0.2
RETRAIN_IF_MISSING = True

logging.basicConfig(
    filename="anomaly_ai_engine.log",
    level=logging.INFO,
    format="%(message)s"
)

model = None  # <-- IMPORTANT


def log_event(event):
    logging.info(json.dumps(event))


# ---------------- MODEL LOADING ----------------
def load_or_train_model():
    global model

    if not os.path.exists("models"):
        os.makedirs("models")

    if os.path.exists(MODEL_PATH):
        print(Fore.GREEN + "[INFO] Loading trained anomaly model...")
        model = joblib.load(MODEL_PATH)

    elif RETRAIN_IF_MISSING:
        print(Fore.YELLOW + "[INFO] No model found. Training baseline model...")

        normal_data = np.random.normal(
            loc=[50, 5, 300],
            scale=[10, 2, 100],
            size=(1000, 3)
        )

        model = IsolationForest(
            contamination=0.05,
            random_state=42
        )

        model.fit(normal_data)
        joblib.dump(model, MODEL_PATH)
        print(Fore.GREEN + "[INFO] Model trained and saved.")

    else:
        raise Exception("No model found.")


# ---------------- FEATURE ENGINEERING ----------------
def extract_features(event):
    return np.array([
        event.get("requests_per_minute", 0),
        event.get("failed_logins", 0),
        event.get("data_transfer_kb", 0)
    ]).reshape(1, -1)


# ---------------- ANOMALY ANALYSIS ----------------
def analyze_event(event):
    global model

    # Lazy load model
    if model is None:
        load_or_train_model()

    features = extract_features(event)

    anomaly_score = model.decision_function(features)[0]
    prediction = model.predict(features)[0]

    if prediction == -1 or anomaly_score < ANOMALY_THRESHOLD:

        alert = {
            "alert": "AI_ANOMALY_DETECTED",
            "event": event,
            "anomaly_score": float(anomaly_score),
            "timestamp": time.time()
        }

        print(Fore.RED + f"[ALERT] AI Anomaly Detected | Score: {anomaly_score:.4f}")
        log_event(alert)
        automated_response(event)

    else:
        print(Fore.GREEN + f"[NORMAL] Behavior OK | Score: {anomaly_score:.4f}")


# ---------------- RESPONSE HOOK ----------------
def automated_response(event):
    print(Fore.YELLOW + "[ACTION] Triggering response module...")


# ---------------- WRAPPER ----------------
def run_anomaly_module(event):
    analyze_event(event)


# ---------------- TEST ----------------
if __name__ == "__main__":
    test_event = {
        "requests_per_minute": 500,
        "failed_logins": 40,
        "data_transfer_kb": 5000
    }

    analyze_event(test_event)