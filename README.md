# AI Phishing Detection System & SOC Dashboard

A production-ready, real-time Security Operations Center (SOC) platform designed to audit URLs, parse emails, decode QR codes, and run computer vision brand spoofing analyses to classify targets into **Legitimate**, **Suspicious**, or **Phishing**. 

Powered by a **Random Forest Classifier** trained on 2,000+ structural features, integrated with WHOIS, DNS, and SSL verification sockets, and equipped with a customizable ReportLab PDF generator.

---

## 🚀 Key Features

1. **Multi-Input Scanning Engine**:
   * **Real-Time URL Scan**: Analyzes lexical indicators and queries domain intelligence.
   * **QR Code Auditor**: Extracts target URLs from uploaded QR codes.
   * **Email Corpus Analyzer**: Inspects headers, analyzes lookalike domains (e.g. sender spoofing), scans embedded links, and evaluates urgency keyword density.
   * **Visual Brand Spoofing Sandbox**: Renders a sandboxed mockup page and checks visual similarity indicators (colors, forms) to detect logo/brand spoofing on unauthorized domains.

2. **Machine Learning Classifier**:
   * Evaluates 13 critical lexical and structural features (URL length, entropy, subdomains, HTTPS presence, redirect loops, shortener masking, suspicious keywords, and dots/hyphens).
   * Random Forest Classifier with detailed performance metrics reporting.

3. **Threat Intelligence Integration**:
   * **WHOIS Sockets**: Computes registrar identities and domain age.
   * **DNS Resolvers**: Resolves A, MX, NS, and TXT records.
   * **SSL/TLS Auditing**: Validates certificate issuers and expiration status.

4. **SOC Analytics Dashboard**:
   * Dark-themed glassmorphism panel.
   * Dynamic stacked bar charts tracking daily audits.
   * Dynamic risk dials.
   * Real-time global threat feeds populated by OpenPhish datasets.

5. **Security Hardening**:
   * Rate limiting on critical endpoints.
   * Clickjacking defense (`X-Frame-Options: DENY`).
   * SQL injection prevention via SQLite parameterized statements.
   * CSRF protection checks and Content-Security-Policy (CSP) headers.

---

## 📂 Project Structure

```text
AI-Phishing-Detector/
├── app.py                      # Main Flask application and advanced scan routes
├── config.py                   # Application secret keys, directories, and limits
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Multi-stage container instructions
├── README.md                   # Comprehensive platform documentation
│
├── database/
│   └── db_manager.py           # SQLite database schema, user accounts & scan logger
│
├── models/
│   └── phishing_model.pkl      # Trained Random Forest classifier binary (generated post-train)
│
├── ml/
│   ├── feature_extractor.py    # URL lexical feature extractor (13 markers)
│   ├── train.py                # Synthetic dataset generator, trainer & evaluator
│   └── predict.py              # ML classifier inference engine & AI Risk Score compiler
│
├── intelligence/
│   ├── whois_lookup.py         # Domain age & registrar lookup module
│   ├── dns_lookup.py           # DNS MX, A, NS, TXT resolver
│   ├── ssl_checker.py          # Port 443 SSL checker
│   └── threat_feed.py          # OpenPhish live indicators ingestion
│
├── reports/
│   └── report_generator.py     # ReportLab PDF compilation module
│
└── static/
    ├── css/
    │   └── style.css           # Premium cyber dark-mode SOC stylesheet
    ├── js/
    │   └── main.js             # AJAX scan pipelines and gauge chart drawing
    └── uploads/                # Directory for temporary file uploads & screenshots
```

---

## ⚙️ Installation & Setup

### Option 1: Local Virtual Environment

**Step 1: Clone the Repository & Navigate**
```bash
cd e:\Phishing
```

**Step 2: Create a Virtual Environment**
```bash
python -m venv venv
venv\Scripts\activate
```

**Step 3: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Step 4: Train the ML Model**
This extracts features and compiles the model binary `models/phishing_model.pkl`.
```bash
python ml/train.py
```

**Step 5: Run the Server**
```bash
python app.py
```
Open [http://localhost:5000](http://localhost:5000) in your browser. Log in using the default administrator credentials:
* **Username**: `admin`
* **Password**: `admin123`

---

### Option 2: Docker Containerization

Deploy the entire infrastructure in a containerized environment (which automatically trains the model on launch):

```bash
# Build the image
docker build -t ai-phishing-detector .

# Run the container mapping port 5000
docker run -p 5000:5000 ai-phishing-detector
```
Access the dashboard at [http://localhost:5000](http://localhost:5000).

---

## 📡 REST API Documentation

The platform exposes endpoints returning JSON data:

### 1. Execute Scan (`POST /scan`)
Scan a URL from an external system.

* **Payload**:
  ```json
  {
    "url": "http://paypal-verification-update.xyz/login"
  }
  ```
* **Response**:
  ```json
  {
    "status": "success",
    "url": "http://paypal-verification-update.xyz/login",
    "verdict": "Phishing",
    "confidence": 0.94,
    "risk_score": 96,
    "scan_time": "2026-06-13 13:05:12",
    "intelligence": {
      "whois": { ... },
      "dns": { ... },
      "ssl": { ... }
    },
    "report_download_api": "/report/download/4"
  }
  ```

### 2. Retrieve Scan History (`GET /history_api`)
List recent scanned indicator metadata.

* **Response**:
  ```json
  [
    {
      "id": 1,
      "url": "http://paypal-verification-update.xyz/login",
      "prediction": "Phishing",
      "risk_score": 96,
      "confidence": 0.94,
      "scan_time": "2026-06-13 13:05:12"
    }
  ]
  ```

### 3. Fetch Report Details (`GET /report/<scan_id>`)
Get detailed analytical data for a specific database scan record.

---

## 🛡️ Security Policies

1. **Password Security**: Analyst passwords are encrypted via Werkzeug PBKDF2 hashing.
2. **CSRF & Session Hijacking**: Web interface is protected with strict session cookies. API routes incorporate independent token architectures.
3. **Clickjacking & XSS Mitigation**: Response headers force `X-Frame-Options: DENY` and lock resources down via Content-Security-Policy (CSP).
