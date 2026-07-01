# AntiPhishing Server

Flask backend for the AntiPhishing Android application.  
Developed by **Yahav Eliyahu & Ron Golan**

---

## Overview

This server is the backend component of a real-time phishing detection system for Android. It receives URLs intercepted by the Android app and runs them through a multi-stage analysis pipeline to determine whether they are malicious.

---

## Detection Pipeline

Every URL goes through the following steps in order:

```
Step 1 — MongoDB lookup (fast path)
    → Whitelisted domain   → Allow immediately
    → Blacklisted domain   → ML model → Block + risk % + explanation
    → Not found            → Continue to Step 2

Step 2 — Lexical Analysis (on Android device)
    → 52 features computed locally
    → Result sent to /api/score

Step 3 — XGBoost ML Model (/api/score)
    → 57-feature vector (52 from Android + 5 derived server-side)
    → Trained on 1.7M URLs, 96.10% accuracy
    → Returns: is_malicious, confidence %, explanation

Step 3b — Domain Age post-processing (WHOIS)
    → Newly registered domains boost malicious confidence
    → Domains > 1 year old slightly reduce suspicion
```

---

## ML Model

| Property | Value |
|---|---|
| Algorithm | XGBoost (Gradient Boosting) |
| Training URLs | 1,721,023 |
| Features | 57 |
| Accuracy | 96.10% |
| AUC-ROC | 0.9924 |
| Miss rate | 4.98% |
| False alarm rate | 2.25% |

**Training data sources:**
- Kaggle Phishing Dataset (651K URLs)
- MongoDB threat intelligence export (811K domains)
- Tranco top 50K safe domains (250K URLs)
- Synthetic phishing patterns (13.5K URLs)
- Common Crawl safe deep paths (5.4K URLs)
- Curated safe URLs (2.1K URLs)

---

## API Endpoints

### `POST /api/check`
Main pipeline entry point. Runs MongoDB lookup and returns result or `unknown` if not found.

**Request:**
```json
{ "url": "https://example.com/login" }
```

**Response:**
```json
{
  "url": "https://example.com/login",
  "is_malicious": true,
  "confidence": 96,
  "match_type": "ml_model",
  "source": "XGBoost + Domain Age",
  "explanation": "Risk: 96%\n• IP address used instead of a domain name\n• ..."
}
```

---

### `POST /api/score`
ML model scoring endpoint. Called by Android after lexical analysis.

**Request:**
```json
{
  "url": "https://example.com/login",
  "features": {
    "url_length": 35,
    "is_https": 1,
    "lexical_risk_score": 20,
    "...": "..."
  }
}
```

**Response:** same shape as `/api/check`

---

### `GET /api/stats`
Returns database statistics.

**Response:**
```json
{
  "malicious_urls": 135000,
  "malicious_domains": 675000,
  "whitelisted_domains": 158,
  "cached_checks": 1240
}
```

---

### `POST /api/report`
Adds a user-confirmed malicious URL to the database.

**Request:**
```json
{ "url": "https://evil.com/phishing" }
```

---

### `POST /api/qr/check`
Same pipeline as `/api/check` but for QR-decoded URLs.

### `POST /api/qr/report`
Saves a QR scan result to MongoDB for history and analytics.

---

## Project Structure

```
AntiPhishing-Server/
├── ml/
│   ├── model.pkl              ← Trained XGBoost model (57 features)
│   └── feature_extractor.py   ← Feature computation (57 features)
├── scripts/
│   ├── app.py                 ← Flask server + ML pipeline
│   ├── lookup.py              ← MongoDB Phase 1 lookup
│   ├── domain_age.py          ← WHOIS-based confidence adjustment
│   ├── feature_extractor.py   ← Server-side feature extraction
│   ├── seed_db.py             ← Seeds threat intelligence data
│   ├── seed_whitelist.py      ← Seeds whitelisted domains
│   ├── cleanup_db.py          ← Database cleanup utilities
│   └── scheduler.py           ← Periodic DB update scheduler
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .gitignore
```

---

## Running Locally

```bash
# Clone the repo
git clone https://github.com/yahaveliyahu/AntiPhishing-Server.git
cd AntiPhishing-Server

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Set environment variables
set MONGO_URI=your_atlas_connection_string
set DB_NAME=antiphishing

# Run the server
python scripts/app.py
```

Server runs on `http://localhost:5000`

---

## Deployment

Currently deployed on **Render** (free tier):  
**https://antiphishing-server.onrender.com**

The free tier spins down after 15 minutes of inactivity — the first request after idle may take ~50 seconds to wake the server.

Docker-based deployment — Render reads the `Dockerfile` directly and runs Gunicorn as the production WSGI server.

---

## Tech Stack

- **Python 3.11**
- **Flask** — web framework
- **XGBoost** — ML model
- **scikit-learn** — model pipeline
- **MongoDB Atlas** — threat intelligence database
- **python-whois** — domain age lookup
- **tldextract** — domain parsing
- **Gunicorn** — production WSGI server
- **Docker** — containerization
