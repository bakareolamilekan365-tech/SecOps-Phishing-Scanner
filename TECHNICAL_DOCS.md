# Technical Documentation

## Model Architecture
The core engine has moved from a single Random Forest to a **VotingClassifier** consisting of:
1. Random Forest (100 estimators)
2. XGBoost (LogLoss optimized)
3. Logistic Regression
The soft-voting consensus prevents over-fitting to old phishing trends and balances out edge-cases.

## Feature Set
12 distinct features are extracted per URL, including:
- **Shannon Entropy:** Detects auto-generated / random strings (like DGA domains).
- **At-Symbol (`@`):** Commonly used for credential stuffing or hiding final destinations.
- **WHOIS Domain Age:** Newly registered domains (under 30 days) combined with high brand-similarity are heavily penalized.
- Standard checks (Length, dots, hyphens, HTTPS, suspicious terms, known brands, high-risk TLDs).

## Security Hardening
- **SSRF Block:** `requests.get` will reject resolving `127.x.x.x`, `192.168.x.x`, and `10.x.x.x`.
- **DoS Protection:** 3-second hard timeout for head/get ping operations.
- **Schema Sanitization:** `javascript:` and `data:` schemes are strictly rejected on the backend.
