# SecOps Phishing Scanner

A Hybrid AI-Heuristic production-grade SOC tool that uses Machine Learning to detect malicious, typosquatted, and parked domains. 

## Features
- **Tri-Model Ensemble Engine:** Combines Random Forest, XGBoost, and Logistic Regression for highly accurate threat voting.
- **2019-2026 Threat Intelligence:** Trained on verified JPCERTCC datasets combined with generated safe-domain profiles.
- **Parked Domain & Redirect Detection:** Blocks hidden logic, 'For Sale' domains, and malicious Telegram/X redirects.
- **Intent vs. Identity:** Uses Levenshtein distance & WHOIS domain age to provide nuanced "Caution" vs "Phishing" alerts.
- **Zero-Trust Hardening:** Blocks SSRF network scans and non-HTTP schemas locally.

## Getting Started
1. `pip install -r requirements.txt`
2. `python train_model.py` (Downloads dataset, compiles synthetic data, trains the Tri-Model Joblib).
3. `python app.py` (Starts the Flask SOC UI locally).
