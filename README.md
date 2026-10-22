# 🛡️ LinkShield — Cyber Threat & Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**LinkShield** is an intelligent web security application designed to analyze suspicious URLs and detect phishing threats before they cause harm. Combining **heuristic lexical analysis** with a trained **Random Forest Machine Learning model**, LinkShield provides real-time threat verdicts, risk percentages, and detailed security breakdown checks.

---

##  Key Features

- ** Intelligent URL Scanner**: Decomposes URLs into lexical and structural components to flag potential fraud vectors in real time (<50ms).
- ** Machine Learning Threat Engine**: Powered by a trained **Random Forest classifier** evaluating 10+ URL features with a **99%+ detection rate**.
- ** Granular Risk Scoring**: Provides a calibrated security risk percentage and itemized pass/warning checks for each scanned link.
- ** User Authentication**: Secure registration, login, and password hashing (`pbkdf2:sha256`) with MySQL session management.
- ** Telemetry & Scan Audit Log**: Maintains a chronological scan history allowing users to track previous audits and review historical verdicts.
- ** Editorial Architectural UI**: Designed with a high-end minimalist editorial aesthetic featuring warm parchment canvas, terracotta coral accents, and SVG vector micro-interactions.

---

##  Technology Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Backend** | Python, Flask, Werkzeug | RESTful API and static web server |
| **Machine Learning** | Scikit-Learn, Joblib, Pandas | Random Forest classification model |
| **Frontend** | Semantic HTML5, Vanilla CSS3, JavaScript | Editorial responsive layout, no bulky frameworks |
| **Database** | MySQL | Stores user accounts, sessions, and scan history |
| **Typography** | Syne, Space Grotesk, Plus Jakarta Sans | Modernist editorial font system |

---

##  Machine Learning Engine

LinkShield extracts key lexical, structural, and entropy features from each submitted URL:

1. **URL Length & Host Length** — Detects unusually long URLs used in masking attacks.
2. **IP Address Usage** — Flags URLs that use raw IP addresses instead of registered domain names.
3. **Suspicious Keyword Tokens** — Identifies phishing triggers (e.g., `login`, `verify`, `secure`, `banking`, `update`).
4. **Special Character Density** — Analyzes `@`, `//`, `-`, and redirect delimiters.
5. **Subdomain Count & Depth** — Flags deceptive multi-tier subdomain structures.
6. **HTTPS & Protocol Verification** — Inspects scheme legitimacy.

---

##  Project Structure

```text
LinkShield project/
├── ml/
│   ├── phishing_model_new.pkl      # Trained Random Forest model (Required)
│   ├── train_model.py              # Model training script
│   └── test_model.py               # Standalone model validation script
├── app.py                          # Flask backend API & routing
├── index.html                      # Homepage & hero overview
├── scanner.html                    # URL scanner interface
├── result.html                     # Security analysis verdict view
├── history.html                    # Scan activity audit log
├── login.html                      # Authentication sign-in
├── register.html                   # Account registration
├── script.js                       # Client-side API integration
├── style.css                       # Complete design system & responsive styles
└── requirements.txt                # Python package dependencies
```

---

##  Getting Started

### Prerequisites

Ensure you have the following installed:
- [Python 3.9+](https://www.python.org/downloads/)
- [MySQL Server](https://dev.mysql.com/downloads/installer/) (or XAMPP / MariaDB)

---

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/linkshield.git
cd linkshield
```

---

### 2. Set Up a Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Configure MySQL Database

Open your MySQL client or phpMyAdmin and execute:

```sql
CREATE DATABASE IF NOT EXISTS linkshield;

USE linkshield;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan history table
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    url TEXT NOT NULL,
    safe BOOLEAN NOT NULL,
    risk_score FLOAT DEFAULT NULL,
    prediction VARCHAR(50) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

> **Note:** If your MySQL database credentials differ from the defaults (`root` with no password on `localhost:3306`), configure them via environment variables:
> - `MYSQL_HOST` (default: `127.0.0.1`)
> - `MYSQL_PORT` (default: `3306`)
> - `MYSQL_USER` (default: `root`)
> - `MYSQL_PASSWORD` (default: `""`)
> - `MYSQL_DATABASE` (default: `linkshield`)

---

### 5. Run the Application

```bash
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

##  Security Best Practices Implemented

- **Password Hashing**: Uses Werkzeug's cryptographic `generate_password_hash` with salt.
- **SQL Injection Prevention**: All SQL queries use parameterized prepared statements.
- **XSS Protection**: HTML entities escaped on client-side rendering.
- **Session Protection**: Flask secret key managed securely via environment variable.

---

##  License

This project is licensed under the [MIT License](LICENSE).
