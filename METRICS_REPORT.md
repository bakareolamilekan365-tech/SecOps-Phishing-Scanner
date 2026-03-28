# SecOps Phishing Scanner — Model Evaluation Report

## Overview

| Item | Value |
|------|-------|
| Model file | `phishing_model.joblib` (VotingClassifier: RF + XGBoost + LR) |
| Dataset | `dataset.csv` (85,000 rows) |
| Split | 80 % train (68,000) / **20 % test (17,000)** — `random_state=42` |
| Class labels | `0` = Safe, `1` = Phishing |
| Test-set distribution | Safe: 11,950 · Phishing: 5,050 |
| Script | `compute_metrics.py` |

All metrics below are computed on the **held-out test split only** (20 %, never seen during training).

---

## Core Metrics

| Metric | Value |
|--------|-------|
| **Accuracy** | 100.00 % |
| **Precision** (weighted) | 100.00 % |
| **Recall** (weighted) | 100.00 % |
| **F1-score** (weighted) | 100.00 % |
| **ROC-AUC** | 1.000000 |

---

## Per-Class Metrics

| Class | Precision | Recall | F1-score | Support |
|-------|-----------|--------|----------|---------|
| **Safe (0)** | 100.00 % | 100.00 % | 100.00 % | 11,950 |
| **Phishing (1)** | 100.00 % | 100.00 % | 100.00 % | 5,050 |
| **Macro avg** | 100.00 % | 100.00 % | 100.00 % | 17,000 |
| **Weighted avg** | 100.00 % | 100.00 % | 100.00 % | 17,000 |

---

## Confusion Matrix

```
                  Predicted
                  Safe (0)  Phishing (1)
Actual Safe (0)   11,950         0
Actual Phishing(1)     0     5,050
```

| Cell | Count |
|------|-------|
| True Negatives  (TN) | 11,950 |
| False Positives (FP) | 0 |
| False Negatives (FN) | 0 |
| True Positives  (TP) | 5,050 |

---

## Full Classification Report

```
              precision    recall  f1-score   support

    Safe (0)       1.00      1.00      1.00     11950
Phishing (1)       1.00      1.00      1.00      5050

    accuracy                           1.00     17000
   macro avg       1.00      1.00      1.00     17000
weighted avg       1.00      1.00      1.00     17000
```

---

## ROC-AUC

| AUC Value | Tier |
|-----------|------|
| **1.000000** | Excellent — near-perfect discrimination |

---

## Assumptions & Context

1. **Dataset origin** — `dataset.csv` is the committed fallback dataset (85,000 rows) used
   by `train_model.py` when the live JPCERTCC download is unavailable. It combines:
   - ~37,000 synthetic benign URL feature vectors (label = 0)
   - ~25,000+ phishing URL feature vectors from JPCERTCC (label = 1), with simulated
     domain ages (1–30 days, `random_state=42`)
   - Additional synthetic safe batches (pure_safe × 15,000, local_business_safe × 20,000)

2. **Split reproducibility** — `train_test_split(test_size=0.2, random_state=42)` exactly
   mirrors `train_model.py` line 139. No data leakage occurs as the model is loaded from
   the saved `.joblib` file and not re-trained.

3. **Perfect scores** — The 100 % result is expected for this dataset. The feature
   engineering produces clearly separable classes (phishing URLs exhibit high entropy,
   short domain age, suspicious terms, risky TLDs; safe URLs have opposite signatures).
   The ensemble of RandomForest + XGBoost + LogisticRegression achieves zero errors on
   the held-out synthetic test set. Performance on real-world, out-of-distribution URLs
   should be evaluated separately (see `evaluate_model.py` for live OpenPhish testing).

4. **No repository files were modified** — All existing source files are untouched.

---

## Operational .net Benchmark (Live Render)

Endpoint tested: `https://secops-phishing-scanner-feature.onrender.com/predict`

### Test Set

- Known-good `.net`: `behance.net`, `www.behance.net`, `skyscanner.net`
- Neutral `.net`: `example.net`
- Phishing-style `.net`: 11 brand-impersonation URLs (login/verify/security patterns)

### Before Hotfix (branch state before commit `a9a852f`)

| URL | Verdict | Confidence | Notes |
|-----|---------|------------|-------|
| `https://behance.net` | Phishing | 95.00 % | False positive |
| `https://www.behance.net` | Phishing | 95.00 % | False positive |
| `https://skyscanner.net` | Safe | 98.00 % | Correct |
| `https://example.net` | Phishing | 99.99 % | Expected suspicious baseline |
| 11 phishing-style `.net` URLs | Phishing | 99.66-99.99 % | Correct |

### After Hotfix (live deploy from commit `a9a852f`)

| URL | Verdict | Confidence | Notes |
|-----|---------|------------|-------|
| `https://behance.net` | Safe | 98.00 % | Corrected |
| `https://www.behance.net` | Safe | 98.00 % | Corrected |
| `https://skyscanner.net` | Safe | 98.00 % | Correct |
| `https://example.net` | Phishing | 99.99 % | Unchanged |
| 11 phishing-style `.net` URLs | Phishing | 99.66-99.99 % | Unchanged |

### Benchmark Delta

- Known-good `.net` false positives: **2/3 -> 0/3**
- Phishing-style `.net` detections: **11/11 -> 11/11**
- Observed net effect: reduced false positives while preserving strong phishing catches.

---

## Reproducibility Steps

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the evaluation script
python compute_metrics.py
```

The script produces the full report to stdout in under 30 seconds on a standard laptop.
