# 🛡️ Password Strength Evaluation Based on Modern Attack Techniques

> **Offensive Threat Intelligence Engine trained on a 30.4 Million Record Threat Corpus**  
> *Replacing legacy static-rule password checkers with real-time attack simulation, multi-hardware crack-time estimation, structural pattern masks, and Shannon entropy analysis.*

---

## 📌 Project Overview

**Password Strength Evaluation Based on Modern Attack Techniques** is an enterprise-grade, real-time Security Operations Center (SOC) dashboard designed to evaluate password security against modern offensive attack techniques rather than outdated static rulesets (such as requiring 8 characters with 1 uppercase letter and 1 symbol).

While traditional checkers approve predictable passwords like `Summer2024!` (which satisfy standard rules but are trivially cracked in seconds by GPU dictionary masks), this platform instantly matches passwords against a **30.4 Million record threat intelligence dataset**, identifies structural patterns, computes exact Shannon entropy, and benchmarks crack times across single CPUs, consumer GPUs, and high-end GPU clusters.

---

## 🔥 Key Features

- **⚡ 30.4 Million In-Memory Threat Corpus**: Ingests and indexes over **30,441,042 breach records and dictionary entries** into a high-speed memory set, delivering **sub-millisecond set lookup latency (0.0076 ms)** per evaluation.
- **🎯 6-Step Real-Time Threat Pipeline**:
  1. **Input Capture**: Zero-latency input handling on every keystroke.
  2. **Preprocessing & Normalization**: Categorizes uppercase, lowercase, numeric, and special character sets.
  3. **30.4M Threat Corpus Match**: Performs frequency rank lookup against leaked breach databases.
  4. **Structural Pattern Mask Analysis**: Detects word-year-symbol masks (`BaseWord + 202X + !`), sequential series (`123456`), keyboard walks (`qwerty`), and repeated characters.
  5. **Attacker Hardware Crack Estimates**: Computes log-scale crack times across Single CPU, Consumer GPU, and High-End GPU clusters using `zxcvbn`.
  6. **Threat Score & Remediation**: Generates a normalized score (0–100), risk verdict, and actionable remediation advice.
- **📊 Real-Time Chart.js Visualizations**: Dynamic log-scale bar graph comparing estimated time-to-compromise across hardware tiers.
- **🔑 Cryptographically Strong Generator**: Built-in customizable password generator leveraging Python's `secrets` and `random` primitives.
- **📄 Formal Print-Ready Audit Report (`/result`)**: Generates an enterprise evaluation report ready for compliance exporting and security audits.
- **🔒 Local-First & Zero-Storage Privacy**: No input passwords leave the application or get logged to disk; evaluations occur entirely in-memory.

---

## 🏗️ System Architecture & Workflow

```
[ User Input Password ]
          │
          ▼
┌──────────────────────────┐
│  Step 1: Input Capture   │
└─────────┬────────────────┘
          │
          ▼
┌──────────────────────────┐
│  Step 2: Preprocess &    │
│  Normalize Character Sets│
└─────────┬────────────────┘
          │
          ▼
┌──────────────────────────┐
│  Step 3: In-Memory 30.4M │ ──► Trained Datasets:
│  Threat Database Match   │     • global_breach_corpus.txt (14.34M)
└─────────┬────────────────┘     • extended_threat_corpus.txt (16.00M)
          │                      • high_risk_passwords.txt (48.3K)
          ▼                      • breach_root_patterns.txt (44)
┌──────────────────────────┐
│ Step 4: Structural Mask  │
│ & Pattern Analysis       │
└─────────┬────────────────┘
          │
          ▼
┌──────────────────────────┐
│ Step 5: Shannon Entropy  │
│ & Multi-GPU Crack-Time   │
└─────────┬────────────────┘
          │
          ▼
┌──────────────────────────┐
│ Step 6: Normalized Score │ ──► Score Output (0 - 100), Risk Verdict,
│ & Executive Remediation  │     Chart.js Visuals, Formal PDF Report
└──────────────────────────┘
```

---

## 📊 Traditional Systems vs Modern Threat Evaluation

| Feature Aspect | Traditional Password Checkers | Modern Threat Evaluation Platform |
| :--- | :--- | :--- |
| **Evaluation Strategy** | Static rules (Min 8 chars, 1 uppercase, 1 symbol) | Offensive Attack Simulation & Data-driven Threat Intelligence |
| **Breach Database Check** | None (Allows weak dictionary terms like `Summer2024!`) | **30.4 Million Record Breach Lookup** |
| **Feedback Quality** | Generic error messages ("Add special character") | Exact Structural Mask & Term Match Explanations |
| **Hardware Resistance** | Arbitrary "Weak / Strong" rating | Multi-Hardware Crack-Time Estimations (CPU vs Consumer GPU vs GPU Cluster) |
| **Data Privacy** | Frequently calls 3rd-party web APIs | **100% Local-First In-Memory Processing** |

---

## 🛠️ Technology Stack

- **Backend**: Python 3.11, Flask, Gunicorn (Production WSGI)
- **Security Engine**: `zxcvbn-python`, `hashlib`, `bcrypt`, `re` (Pattern Regex)
- **Frontend**: HTML5, Vanilla CSS3 (Custom Dark SOC Theme & Glassmorphism), JavaScript (ES6+ Async API)
- **Visuals & Fonts**: `Chart.js` (Logarithmic Crack Graph), FontAwesome 6, Inter & JetBrains Mono Fonts
- **Deployment**: Render.com Blueprint (`render.yaml`), Heroku / Docker (`Procfile`)

---

## 📂 Project Directory Structure

```
Mini Project IS/
├── app.py                      # Flask Application Controller & Threat Evaluation Engine
├── Procfile                    # WSGI Web Process Definition for Production Deployment
├── render.yaml                 # Render.com Blueprint Infrastructure File
├── requirements.txt            # Production Python Dependencies
├── RENDER_DEPLOYMENT.md        # Step-by-Step Render Deployment Guide
├── README.md                   # Comprehensive Project Documentation
├── datasets/                   # 30.4M Record Threat Intelligence Dataset Corpus
│   ├── breach_root_patterns.txt   # Base roots, security terms, & leetspeak rules
│   ├── common_passwords.txt       # Base dictionary lookup wordlist (48,309 entries)
│   ├── extended_threat_corpus.txt # High-probability suffix variations (16,000,000 entries)
│   ├── global_breach_corpus.txt   # Global breach database (14,344,391 entries)
│   └── high_risk_passwords.txt    # High-frequency leak dataset (48,309 entries)
├── static/
│   ├── css/
│   │   └── style.css           # Modern Cyberpunk / SOC Dashboard Styling
│   └── js/
│       └── main.js             # Async Real-time Event Handlers & Chart.js Controllers
└── templates/
    ├── index.html              # Main Threat Evaluation SOC Dashboard UI
    └── result.html             # Print-ready Formal Security Audit Report
```

---

## 🚀 Local Installation & Setup

### Prerequisites
- **Python 3.9+** installed on your system.

### Steps
1. **Clone or Extract the Repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Password-Strength-Evaluation.git
   cd Password-Strength-Evaluation
   ```

2. **Create a Virtual Environment (Optional but Recommended)**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the Local Server**:
   ```bash
   python app.py
   ```

5. **Access the Dashboard**:
   Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 🌐 Deploying to Render.com

This project includes pre-configured **`render.yaml`** and **`Procfile`** blueprints for instant deployment on [Render.com](https://render.com/).

### Deployment Steps:
1. Push your repository to **GitHub / GitLab**.
2. Sign in to **[Render.com Dashboard](https://dashboard.render.com/)**.
3. Click **New +** → Select **Web Service**.
4. Connect your GitHub repository.
5. Set the build parameters:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT`
6. Click **Create Web Service**.

For detailed deployment instructions, refer to [RENDER_DEPLOYMENT.md](RENDER_DEPLOYMENT.md).

---

## 🔌 API Endpoints Reference

### 1. `POST /evaluate`
Evaluates an input password against the 30.4M threat corpus, structural masks, entropy, and hardware crack profiles.

- **Request Body** (`application/json`):
  ```json
  {
    "password": "CyberShield2026!"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "score": 75,
    "verdict": "Strong",
    "color": "#00f0ff",
    "entropy": 62.4,
    "dict_match": true,
    "dict_message": "Breach Pattern Match: Contains common root term ('cyber') from threat corpus",
    "pattern_summary": "Contains 4-digit calendar year ('2026')",
    "attacker_profiles": {
      "cpu_time": "12 years",
      "gpu_time": "4 days",
      "high_gpu_time": "1 hour"
    },
    "suggestion": "Strong security level! Ensure password uniqueness across sites.",
    "dataset_count": 30441042
  }
  ```

---

### 2. `GET /generate`
Generates a cryptographically randomized password evaluated against the threat model.

- **Query Parameters**:
  - `length` (default: `16`)
  - `uppercase` (`true`/`false`)
  - `lowercase` (`true`/`false`)
  - `numbers` (`true`/`false`)
  - `symbols` (`true`/`false`)

- **Example**: `GET /generate?length=16&symbols=true`

---

### 3. `GET /result`
Renders the print-friendly formal security audit report page parsing audit parameters from the query string (`?pwd=...`).

---

## 🛡️ License & Educational Disclaimer

This project is created for **cybersecurity research, educational demonstrations, and security awareness auditing**. All dataset processing occurs locally without unauthorized transmission of user data.
