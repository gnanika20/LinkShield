from flask import Flask, request, jsonify, session, send_from_directory
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
import re
from datetime import datetime
import os
import joblib
import pandas as pd
app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "linkshield-dev-secret-change-me"
)
DB_CONFIG = {
    "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.environ.get("MYSQL_PORT", "3306")),
    "user": os.environ.get("MYSQL_USER", "root"),
    "password": os.environ.get("MYSQL_PASSWORD", ""),
    "database": os.environ.get("MYSQL_DATABASE", "linkshield"),
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# =========================================================
# ML MODEL CONFIGURATION
# =========================================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "phishing_model_new.pkl"
)

# Load the trained Random Forest model
model = joblib.load(MODEL_PATH)


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db():
    """Create a new MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)


# =========================================================
# URL VALIDATION
# =========================================================

def valid_url(url):
    """Basic URL validation."""
    try:
        parsed = urlparse(url)

        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.netloc)
        )

    except Exception:
        return False


# =========================================================
# ML FEATURE EXTRACTION
# Must match the features used while training the model.
# =========================================================

SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "passwd",
    "bank",
    "secure",
    "update",
    "confirm",
    "authenticate",
    "wallet",
    "payment",
    "billing",
    "credential"
]


def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""

    if not text:
        return 0.0

    from collections import Counter
    import math

    counts = Counter(text)
    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_features(url):
    """
    Extract the same 10 features used during model training.

    Feature order:
    1. url_length
    2. num_dots
    3. has_https
    4. has_ip
    5. num_subdirs
    6. num_params
    7. suspicious_words
    8. special_char_count
    9. digits_count
    10. entropy
    """

    parsed = urlparse(url)

    # URL length
    url_length = len(url)

    # Number of dots
    num_dots = url.count(".")

    # HTTPS
    has_https = 1 if parsed.scheme == "https" else 0

    # IP address detection
    has_ip = 1 if re.search(
        r"^(?:\d{1,3}\.){3}\d{1,3}$",
        parsed.hostname or ""
    ) else 0

    # Number of subdirectories
    path = parsed.path.strip("/")

    if path:
        num_subdirs = len(path.split("/"))
    else:
        num_subdirs = 0

    # Number of parameters
    num_params = len(
        parsed.query.split("&")
    ) if parsed.query else 0

    # Suspicious words
    lower_url = url.lower()

    suspicious_word_count = sum(
        1 for word in SUSPICIOUS_WORDS
        if word in lower_url
    )

    # Special characters
    special_char_count = sum(
        1 for char in url
        if not char.isalnum()
        and char not in "/:."
    )

    # Digits
    digits_count = sum(
        1 for char in url
        if char.isdigit()
    )

    # Entropy
    entropy = calculate_entropy(url)

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "has_https": has_https,
        "has_ip": has_ip,
        "num_subdirs": num_subdirs,
        "num_params": num_params,
        "suspicious_words": suspicious_word_count,
        "special_char_count": special_char_count,
        "digits_count": digits_count,
        "entropy": entropy
    }


# =========================================================
# ML URL ANALYSIS
# =========================================================

def analyze_url(url):
    """
    Analyze a URL using the trained Random Forest model.

    Returns:
        is_safe,
        prediction,
        risk_score,
        reasons
    """

    # Extract features
    features = extract_features(url)

    # Convert features into DataFrame
    features_df = pd.DataFrame([features])

    # Get prediction
    prediction_value = int(
        model.predict(features_df)[0]
    )

    # Get probability
    probabilities = model.predict_proba(features_df)[0]

    # Probability of phishing
    phishing_probability = float(
        probabilities[1] * 100
    )

    # -----------------------------------------------------
    # Prediction
    # -----------------------------------------------------

    if prediction_value == 1:
        prediction = "Phishing"
        is_safe = False
        risk_score = phishing_probability
    else:
        prediction = "Legitimate"
        is_safe = True
        risk_score = phishing_probability

    # -----------------------------------------------------
    # Explanation / Reasons
    # These are based on URL characteristics.
    # -----------------------------------------------------

    reasons = []

    lower_url = url.lower()

    # HTTPS
    if not url.lower().startswith("https://"):
        reasons.append(
            "Website does not use HTTPS"
        )
    else:
        reasons.append(
            "HTTPS security detected"
        )

    # IP address
    if features["has_ip"] == 1:
        reasons.append(
            "Uses an IP address instead of a domain"
        )

    # Long URL
    if features["url_length"] > 90:
        reasons.append(
            "URL is unusually long"
        )

    # Suspicious keywords
    found_words = []

    for word in SUSPICIOUS_WORDS:
        if word in lower_url:
            found_words.append(word)

    if found_words:
        for word in found_words[:3]:
            reasons.append(
                "Contains suspicious keyword: " + word
            )

    # @ symbol
    if "@" in url:
        reasons.append(
            "Contains suspicious @ symbol"
        )

    # Many dots
    if features["num_dots"] >= 3:
        reasons.append(
            "Contains an unusually high number of dots/subdomains"
        )

    # Many digits
    if features["digits_count"] >= 5:
        reasons.append(
            "Contains an unusually high number of digits"
        )

    # High entropy
    if features["entropy"] >= 4.5:
        reasons.append(
            "Contains a highly random-looking URL structure"
        )

    # -----------------------------------------------------
    # Legitimate URL explanation
    # -----------------------------------------------------

    if is_safe:

        # If no negative indicators were found
        if not any(
            phrase in " ".join(reasons)
            for phrase in [
                "does not use HTTPS",
                "IP address",
                "unusually long",
                "suspicious keyword",
                "suspicious @",
                "unusually high",
                "random-looking"
            ]
        ):
            reasons = [
                "HTTPS security detected",
                "URL structure appears normal",
                "No strong phishing indicators detected"
            ]

        else:
            reasons.append(
                "ML model classified the URL as legitimate"
            )

    # -----------------------------------------------------
    # Phishing explanation
    # -----------------------------------------------------

    else:

        reasons.append(
            "ML model detected characteristics associated with phishing URLs"
        )

    # Make sure risk score stays between 0 and 100
    risk_score = max(
        0.0,
        min(100.0, risk_score)
    )

    return (
        is_safe,
        prediction,
        float(risk_score),
        reasons
    )


# =========================================================
# REGISTER
# =========================================================

@app.route("/api/register", methods=["POST"])
def register():

    data = request.get_json(silent=True) or {}

    name = str(
        data.get("name", "")
    ).strip()

    email = str(
        data.get("email", "")
    ).strip().lower()

    password = str(
        data.get("password", "")
    )

    if not name or not email or not password:

        return jsonify({
            "success": False,
            "message": "Please fill all fields."
        }), 400

    if len(password) < 6:

        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters."
        }), 400

    password_hash = generate_password_hash(
        password
    )

    conn = None
    cursor = None

    try:

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users
                (name, email, password_hash)
            VALUES
                (%s, %s, %s)
            """,
            (
                name,
                email,
                password_hash
            )
        )

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Account created successfully!"
        }), 201

    except Error as e:

        if getattr(e, "errno", None) == 1062:

            return jsonify({
                "success": False,
                "message": "An account with this email already exists."
            }), 409

        return jsonify({
            "success": False,
            "message": "Database error during registration."
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn and conn.is_connected():
            conn.close()


# =========================================================
# LOGIN
# =========================================================

@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    email = str(
        data.get("email", "")
    ).strip().lower()

    password = str(
        data.get("password", "")
    )

    if not email or not password:

        return jsonify({
            "success": False,
            "message": "Please enter email and password."
        }), 400

    conn = None
    cursor = None

    try:

        conn = get_db()
        cursor = conn.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                name,
                email,
                password_hash
            FROM users
            WHERE email = %s
            LIMIT 1
            """,
            (email,)
        )

        user = cursor.fetchone()

        if not user or not check_password_hash(
            user["password_hash"],
            password
        ):

            return jsonify({
                "success": False,
                "message": "Invalid login details."
            }), 401

        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]

        return jsonify({
            "success": True,
            "message": "Login successful!",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"]
            }
        })

    except Error:

        return jsonify({
            "success": False,
            "message": "Database error during login."
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn and conn.is_connected():
            conn.close()


# =========================================================
# LOGOUT
# =========================================================

@app.route("/api/logout", methods=["POST"])
def logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "You have been logged out."
    })


# =========================================================
# SESSION
# =========================================================

@app.route("/api/session", methods=["GET"])
def current_session():

    if "user_id" not in session:

        return jsonify({
            "loggedIn": False
        })

    return jsonify({
        "loggedIn": True,
        "user": {
            "id": session["user_id"],
            "name": session["user_name"],
            "email": session["user_email"]
        }
    })


# =========================================================
# SCAN URL
# =========================================================

@app.route("/api/scan", methods=["POST"])
def scan():

    if "user_id" not in session:

        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    url = str(
        data.get("url", "")
    ).strip()

    if not url:

        return jsonify({
            "success": False,
            "message": "Please enter a URL."
        }), 400

    if len(url) > 2048:

        return jsonify({
            "success": False,
            "message": "URL is too long."
        }), 400

    if not valid_url(url):

        return jsonify({
            "success": False,
            "message": (
                "Please enter a valid URL beginning "
                "with http:// or https://."
            )
        }), 400

    # =====================================================
    # ML ANALYSIS
    # =====================================================

    is_safe, prediction, risk_score, reasons = analyze_url(url)

    conn = None
    cursor = None

    try:

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans
                (
                    user_id,
                    url,
                    is_safe,
                    prediction,
                    risk_score
                )
            VALUES
                (%s, %s, %s, %s, %s)
            """,
            (
                session["user_id"],
                url,
                is_safe,
                prediction,
                risk_score
            )
        )

        scan_id = cursor.lastrowid

        # Save reasons
        for reason in reasons:

            cursor.execute(
                """
                INSERT INTO scan_reasons
                    (scan_id, reason)
                VALUES
                    (%s, %s)
                """,
                (
                    scan_id,
                    reason
                )
            )

        conn.commit()

        result = {
            "id": scan_id,
            "url": url,
            "safe": is_safe,
            "is_safe": is_safe,
            "prediction": prediction,
            "risk_score": risk_score,
            "reasons": reasons,
            "date": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }

        return jsonify({
            "success": True,
            "result": result
        }), 201

    except Error:

        if conn:
            conn.rollback()

        return jsonify({
            "success": False,
            "message": "Database error while saving scan."
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn and conn.is_connected():
            conn.close()


# =========================================================
# LATEST RESULT
# =========================================================

@app.route("/api/scan/latest", methods=["GET"])
def latest_scan():

    if "user_id" not in session:

        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    conn = None
    cursor = None

    try:

        conn = get_db()

        cursor = conn.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                url,
                is_safe,
                prediction,
                risk_score,
                scanned_at
            FROM scans
            WHERE user_id = %s
            ORDER BY scanned_at DESC, id DESC
            LIMIT 1
            """,
            (
                session["user_id"],
            )
        )

        scan_row = cursor.fetchone()

        if not scan_row:

            return jsonify({
                "success": True,
                "result": None
            })

        cursor.execute(
            """
            SELECT reason
            FROM scan_reasons
            WHERE scan_id = %s
            ORDER BY id
            """,
            (
                scan_row["id"],
            )
        )

        reasons = [
            row["reason"]
            for row in cursor.fetchall()
        ]

        result = {
            "id": scan_row["id"],
            "url": scan_row["url"],
            "safe": bool(
                scan_row["is_safe"]
            ),
            "is_safe": bool(
                scan_row["is_safe"]
            ),
            "prediction": scan_row["prediction"],
            "risk_score": (
                float(scan_row["risk_score"])
                if scan_row["risk_score"] is not None
                else None
            ),
            "reasons": reasons,
            "date": scan_row["scanned_at"].strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }

        return jsonify({
            "success": True,
            "result": result
        })

    except Error:

        return jsonify({
            "success": False,
            "message": "Database error while loading result."
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn and conn.is_connected():
            conn.close()


# =========================================================
# HISTORY
# =========================================================

@app.route("/api/history", methods=["GET"])
def history():

    if "user_id" not in session:

        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    conn = None
    cursor = None

    try:

        conn = get_db()

        cursor = conn.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT
                id,
                url,
                is_safe,
                prediction,
                risk_score,
                scanned_at
            FROM scans
            WHERE user_id = %s
            ORDER BY scanned_at DESC, id DESC
            """,
            (
                session["user_id"],
            )
        )

        rows = cursor.fetchall()

        scans = []

        for row in rows:

            cursor.execute(
                """
                SELECT reason
                FROM scan_reasons
                WHERE scan_id = %s
                ORDER BY id
                """,
                (
                    row["id"],
                )
            )

            reasons = [
                r["reason"]
                for r in cursor.fetchall()
            ]

            scans.append({
                "id": row["id"],
                "url": row["url"],
                "safe": bool(
                    row["is_safe"]
                ),
                "is_safe": bool(
                    row["is_safe"]
                ),
                "prediction": row["prediction"],
                "risk_score": (
                    float(row["risk_score"])
                    if row["risk_score"] is not None
                    else None
                ),
                "reasons": reasons,
                "date": row["scanned_at"].strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            })

        return jsonify({
            "success": True,
            "history": scans
        })

    except Error:

        return jsonify({
            "success": False,
            "message": "Database error while loading history."
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn and conn.is_connected():
            conn.close()

@app.route("/api/history/<int:scan_id>", methods=["GET"])
def history_result(scan_id):

    if "user_id" not in session:

        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    conn = None
    cursor = None

    try:

        conn = get_db()

        cursor = conn.cursor(dictionary=True)

        # Get selected scan
        cursor.execute(
            """
            SELECT
                id,
                url,
                is_safe,
                prediction,
                risk_score,
                scanned_at
            FROM scans
            WHERE id = %s
            AND user_id = %s
            """,
            (
                scan_id,
                session["user_id"]
            )
        )

        scan = cursor.fetchone()

        if not scan:

            return jsonify({
                "success": False,
                "message": "Scan result not found."
            }), 404

        # Get risk reasons
        cursor.execute(
            """
            SELECT reason
            FROM scan_reasons
            WHERE scan_id = %s
            ORDER BY id
            """,
            (scan_id,)
        )

        reasons = [
            row["reason"]
            for row in cursor.fetchall()
        ]

        result = {
            "id": scan["id"],
            "url": scan["url"],
            "safe": bool(scan["is_safe"]),
            "is_safe": bool(scan["is_safe"]),
            "prediction": scan["prediction"],
            "risk_score": (
                float(scan["risk_score"])
                if scan["risk_score"] is not None
                else None
            ),
            "reasons": reasons,
            "date": scan["scanned_at"].strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }

        return jsonify({
            "success": True,
            "result": result
        })

    except Error:

        return jsonify({
            "success": False,
            "message": "Database error while loading result."
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn and conn.is_connected():
            conn.close()
# =========================================================
# CLEAR HISTORY
# =========================================================

@app.route("/api/history", methods=["DELETE"])
def clear_history():

    if "user_id" not in session:

        return jsonify({
            "success": False,
            "message": "Please login first."
        }), 401

    conn = None
    cursor = None

    try:

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM scans
            WHERE user_id = %s
            """,
            (
                session["user_id"],
            )
        )

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Scan history cleared."
        })

    except Error:

        if conn:
            conn.rollback()

        return jsonify({
            "success": False,
            "message": "Database error while clearing history."
        }), 500

    finally:

        if cursor:
            cursor.close()

        if conn and conn.is_connected():
            conn.close()


# =========================================================
# SERVE FRONTEND
# =========================================================

@app.route("/")
def index():

    return send_from_directory(
        BASE_DIR,
        "index.html"
    )


@app.route("/<path:filename>")
def frontend_files(filename):

    # Prevent API routes from being treated as frontend files.
    if filename.startswith("api/"):

        return jsonify({
            "success": False,
            "message": "Not found"
        }), 404

    return send_from_directory(
        BASE_DIR,
        filename
    )


# =========================================================
# RUN FLASK SERVER
# =========================================================

if __name__ == "__main__":

    print("LinkShield Flask server starting...")
    print("Database:", DB_CONFIG["database"])
    print("ML Model:", MODEL_PATH)
    print("Open: http://127.0.0.1:5000")

    app.run(debug=True)

