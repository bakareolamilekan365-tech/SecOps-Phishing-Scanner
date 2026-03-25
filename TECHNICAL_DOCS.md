# Technical Architecture & Documentation

## Overview

This repository contains a lightweight, high-performance Phishing URL Detection system. The architecture relies on a decoupled Machine Learning training pipeline and a Flask-based RESTful web server. The frontend utilizes vanilla JavaScript with the Fetch API, eliminating the need for heavy frameworks like React or Vue, while maintaining modern UI standards via Tailwind CSS and Chart.js.

## Model Architecture

The primary inference engine is driven by a **Random Forest Classifier** (sklearn.ensemble.RandomForestClassifier).

- **Estimators**: 100 decision trees are utilized to prevent overfitting while maintaining high predictive variance.
- **Why Random Forest?** Phishing detection relies heavily on disjointed, non-linear categorical thresholds (e.g., high dot count + missing HTTPS = phish). Random Forest excels at creating splits for these un-normalized distinct parameters better than Logistic Regression or SVMs without requiring heavy data scaling.

## Feature Engineering (eature_extractor.py)

Rather than relying purely on a bag-of-words or heavy NLP architecture, the application extracts 6 optimized numerical flags from any given URL:

1. **URL Length** (Continuous Integer)
2. **Subdomain Count** (`.` delimiter count)
3. **Hyphenation Checks** (Binary - squat indicator)
4. **Protocol Validation** (Binary - HTTPS)
5. **Suspicious Keyword Detection** (Binary flag scanning for words like login, secure, verify).
6. **Brand Typo-Squatting Detection** (Binary flag targeting specific Homograph strings like paypai or bank-ofamerica).
7. **Safe Brand Presence** (Binary flag mapping highly-trusted global/regional domains).
8. **High-Risk TLDs** (Binary flag penalizing notoriously malicious top-level domains like `.top`, `.xyz`, etc.)
9. **Unencrypted HTTP** (Binary flag explicitly detecting unsecure `http://` protocols).

## Data Sourcing & Pipeline ( rain_model.py)

To ensure high accuracy against zero-day phishing architectures, the dataset pipeline is fully dynamic rather than relying on static or outdated 2010s CSV files:

- **Malicious Dataset**: Dynamically crawls the **JPCERTCC Phishing URL Github Repository**, extracting live monthly feed csv files spanning from 2020 to 2026. These real-world zero-day phishing URLs are parsed, de-duplicated, and randomly **sampled directly to 25,000 domains**. This strict clipping bounds ensure the generated dataset stays exceptionally lean and completely avoids GitHub's 100MB Large File Storage crashes.
- **Benign Baseline Generator**: The pipeline tallies the exact number of malicious URLs returned from GitHub and spawns a mirrored identical volume of "Benign" URLs synthetically (Label=0).
- **False Positive Elimination ("Pure Safe" Injection):** To neutralize the Random Forest's inherent bias against treating short-length, HTTPS-protected secure domains as suspicious (like google.com), the script specifically injects 15,000 highly-curated "Pure Safe" metadata structures. This corrects algorithmic misattribution of 50/50 prediction limits against short tech infrastructure.

## Application Infrastructure (`app.py`)

- **Framework**: Flask (Werkzeug WSGI).
- **Endpoint**: Single `/predict` POST route. Expects JSON payload `{"url": "raw_string"}`.
- **Constraint Handling**: Performs sanitization via auto-prepending `https://` to naked domains and gracefully handles 400 Empty String payloads to prevent server-side 500 error crashing.
- **Offline / Dead Link Interception**: Uses `requests.head()` to determine if a URL is actually active. Marks the payload with `is_live=False` so the frontend can remove false "Proceed Safely" buttons for dead mock sites.
- **Zero-Trust Hardcoded Overrides**: Uses `difflib.get_close_matches` with a `0.72` cutoff against a custom mapping of `KNOWN_BRANDS` (Global + Regional). If a scammer attempts a verified typo (e.g., `jumaii`), the application intercepts the backend pipeline, bypassing the machine learning model entirely to force a **99% Phishing** threat flag. Similarly, exact matches for high-risk TLDs immediately override the ML to ensure bulletproof safety.
- **Dynamic Context Generation**: Utilizes the `tldextract` library to generate dynamic trust "bios" and safe redirection links only if the domain is verified both "Safe" and `is_live`.

## Diagnostics (ot_test.py & valuate_model.py)

- The system includes a penetration payload tester that blasts null strings, whitespaces, high-buffer overflows (1,000+ characters), and typo-squatted domains to verify strict stability before deployment.
- During adversarial real-world OpenPhish testing, Content-based features were appended to math-based heuristics to capture zero-day evasion attempts.
