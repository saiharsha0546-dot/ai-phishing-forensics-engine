# AI-Based Browser & Email Forensics Engine (Project #12)
**Next-Gen Security Operations Center (SOC) Cyber Forensics & Phishing Defense Pipeline**

---

## Overview
This project is an end-to-end cyber forensics and phishing detection platform powered by dual **RandomForest machine learning models** and real-time network/header analysis. It inspects browser histories, live network packets (`tshark`/Scapy), raw email headers (`.eml`), and URL structures to assign a high-fidelity phishing probability score accompanied by explainable AI threat indicators.

### Architecture
```
[Browser History SQLite] ─────┐
                              ├──> Feature Engine ──> Dual RandomForest Models ──> AI Probability Score
[Email (.eml) Headers + NLP] ─┤                                                        │
                              │                                                        ▼
[Live Packet/DNS Sniffer] ────┘                                            [Next-Gen SOC Dashboard]
```

---

## Features & Modules

1. **Dual RandomForest Classifiers (`url_phishing_model.pkl` & `email_phishing_model.pkl`)**:
   - Specialized models trained on 11+ structural/WHOIS/entropy features for URLs, and 10+ header/DKIM/SPF/NLP features for `.eml` emails.
   - Automatically initializes and trains on startup (`train_model.py`) if pre-trained models are not present.

2. **Cross-Platform Browser History Threat Hunter (`history_parser.py`)**:
   - Auto-detects local Google Chrome, Microsoft Edge, and Mozilla Firefox profiles on Windows (`%LOCALAPPDATA%` / `%APPDATA%`) and Linux.
   - Safely copies active SQLite databases before querying to prevent `sqlite3.OperationalError: database is locked` crashes.
   - Includes a rich SOC Simulation Fallback mode for testing inside sandboxed virtual machines.

3. **Comprehensive Email (.eml) Inspector (`email_parser.py`)**:
   - Parses RFC 822 email files and raw text.
   - Verifies SPF & DKIM authentication states, extracts full `Received` IP routing chains, checks for domain spoofing (`From` vs `Return-Path` mismatch), and scores textual body urgency via `TextBlob` NLP sentiment analysis.

4. **Live Packet Sniffer & DNS Intercept (`packet_sniffer.py`)**:
   - Captures live DNS lookups and HTTP request URIs using `tshark` or `Scapy`.
   - Automatically falls back to high-fidelity live SOC network traffic simulation when running without Npcap or elevated privileges.

5. **Next-Gen SOC Forensics Workbench (`app.py`, `index.html`, Bootstrap 5 + Chart.js)**:
   - Rich dark obsidian glassmorphism UI with glowing status indicators and micro-animations.
   - One-click sample test presets, drag-and-drop `.eml` upload, interactive feature breakdown bar charts, and live animated packet timelines.

---

## Quickstart Setup & Launch

We recommend using [`uv`](https://github.com/astral-sh/uv) (or standard `venv` + `pip`) for ultra-fast, clean execution without modifying system Python:

### Using `uv` (Recommended)
```powershell
# In the project root folder (c:\Users\saiha\Downloads\dfi):
uv run python train_model.py
uv run python app.py
```
Then open your browser to **http://localhost:5000**.

### Using Standard Python Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python train_model.py
python app.py
```
Then open your browser to **http://localhost:5000**.

---

## Directory Structure
```
c:\Users\saiha\Downloads\dfi\
├── app.py                   # Main Flask REST API & Web Server
├── feature_extractor.py     # URL & Email Vector Extractor + Entropy/NLP
├── history_parser.py        # Chrome/Edge/Firefox SQLite Forensics Parser
├── email_parser.py          # .eml RFC 822 Parser (Headers, SPF, DKIM, Received IPs)
├── packet_sniffer.py        # Network Packet Sniffer & SOC Simulation Fallback
├── train_model.py           # Dataset Generator & RandomForest Model Trainer
├── requirements.txt         # Python Dependencies
├── README.md                # Documentation
├── models/                  # Stored Trained Classifiers (.pkl)
├── sample_emails/           # Pre-packaged Legitimate vs Phishing .eml Files
├── static/
│   ├── css/style.css        # Premium SOC Dark Mode Glassmorphism Theme
│   └── js/dashboard.js      # Interactive Chart.js & Frontend API Logic
└── templates/
    └── index.html           # SOC Cyber Forensics Workbench Interface
```
