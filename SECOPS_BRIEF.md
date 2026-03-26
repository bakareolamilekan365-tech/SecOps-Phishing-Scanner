# SecOps Technical Brief

## System Architecture
The SecOps Phishing URL Scanner is a Hybrid AI-Heuristic tool. It processes unknown URLs directly through a hardcoded sanitization pipeline before applying a Tri-Model Machine Learning calculation.

## Feature Engineering
The model maps 12 distinct numeric flags to determine intent:
- **Shannon Entropy:** Measures randomness in the domain string. High entropy catches non-dictionary generated domains.
- **Levenshtein Distance:** Compares the input URL against the top 40 known global/regional brands to catch intent spoofing (g00gle vs google).
- **WHOIS Age correlation:** Detects 'burner' domains registered recently by aggressively penalizing matches < 30 days old.

## Threat Workflow
1. User provides a URL.
2. The URL is tested against Regex blocks and SSRF Private IP blocks.
3. Feature extraction checks entropy, hyphens, dots, SSL usage, and Domain Age.
4. The Tri-Model Voting Classifier calculates a mathematical probability.
5. Deterministic Overrides: If the domain is literally "Parked for Sale", or redirects maliciously, the AI score is ignored and status is locked to Phishing.
6. A log is exported to `logs/scan_history.log`.
6. A log is exported to logs/scan_history.log.
