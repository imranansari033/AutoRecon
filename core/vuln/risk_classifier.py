import os
import joblib
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATASET    = os.path.join(BASE_DIR, "data", "cve_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "data", "risk_model.pkl")
FEATURES   = ["cvss_score", "port", "service_type"]

SERVICE_MAP = {
    "SSH": 1, "FTP": 2, "HTTP": 3, "HTTPS": 3,
    "HTTP-ALT": 3, "HTTPS-ALT": 3, "HTTP-ALT2": 3,
    "MYSQL": 4, "POSTGRESQL": 4,
    "RDP": 5, "DNS": 6, "SMB": 7,
    "MONGODB": 8, "REDIS": 8, "ELASTICSEARCH": 8,
    "POP3": 9, "IMAP": 9, "POP3S": 9, "IMAPS": 9,
    "SMTP": 10
}


def train_model():
    """Train Decision Tree on cve_dataset.csv and save model."""
    print("[*] Loading dataset...")
    df = pd.read_csv(DATASET)

    X = df[FEATURES]
    y = df["risk_label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("[*] Training Decision Tree...")
    model = DecisionTreeClassifier(max_depth=5, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n[*] Model Evaluation:")
    print(classification_report(y_test, y_pred, zero_division=0))

    joblib.dump(model, MODEL_PATH)
    print(f"[+] Model saved → {MODEL_PATH}")
    return model


def load_model():
    """Load saved model. Train first if it doesn't exist."""
    if not os.path.exists(MODEL_PATH):
        print("[!] Model not found. Training now...")
        return train_model()
    return joblib.load(MODEL_PATH)


def _make_features(cvss: float, port: int, service: str) -> pd.DataFrame:
    """Build a DataFrame with the same column names used in training."""
    service_type = SERVICE_MAP.get(service.upper(), 3)
    return pd.DataFrame([[cvss, port, service_type]], columns=FEATURES)


def predict_risk(cvss_score: float, port: int, service: str) -> str:
    model = load_model()
    return model.predict(_make_features(cvss_score, port, service))[0]


def classify_scan_results(cve_bulk_result: dict) -> dict:
    """Assign ML risk label to each service from bulk CVE results."""
    model = load_model()
    classified = {}

    for port, data in cve_bulk_result.get("results", {}).items():
        service  = data.get("service", "HTTP")
        version  = data.get("version", "N/A")
        cve_data = data.get("cve_data", {})

        max_score = 0.0
        if cve_data.get("status") == "success":
            for cve in cve_data.get("cves", []):
                score = cve.get("score", 0)
                if isinstance(score, (int, float)) and score > max_score:
                    max_score = float(score)

        risk = model.predict(_make_features(max_score, port, service))[0]

        classified[port] = {
            "service": service,
            "version": version,
            "max_cvss": max_score,
            "risk_level": risk
        }

    return {"status": "success", "classified": classified}


def print_classified(result: dict):
    ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    if not result["classified"]:
        print("\n  No services with version info to classify.\n")
        return

    print("\n" + "=" * 50)
    print("  ML RISK CLASSIFICATION")
    print("=" * 50)
    print(f"  {'PORT':<8} {'SERVICE':<12} {'CVSS':<8} RISK")
    print("-" * 50)
    for port, data in result["classified"].items():
        icon = ICONS.get(data["risk_level"], "⚪")
        print(f"  {port:<8} {data['service']:<12} "
              f"{data['max_cvss']:<8} {icon} {data['risk_level']}")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    print("1. Train model")
    print("2. Quick predict test")
    choice = input("Choose: ")

    if choice == "1":
        train_model()
    elif choice == "2":
        test_cases = [
            (9.8, 80, "HTTP"),
            (8.2, 80, "HTTP"),
            (4.3, 80, "HTTP"),
            (0.0, 22, "SSH"),
        ]
        print("\n  PORT   SERVICE   CVSS   PREDICTION")
        print("  " + "-" * 40)
        for score, port, service in test_cases:
            risk = predict_risk(score, port, service)
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk, "⚪")
            print(f"  {port:<7} {service:<10} {score:<7} {icon} {risk}")
