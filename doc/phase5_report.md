# AI WatchDog --- Phase 5 Report

## Production Inference, Risk Engine & Validation

**Project:** AI WatchDog\
**Phase:** 5\
**Status:** PASS\
**Purpose:** Convert the validated Phase 4 ML model into a reusable
inference engine suitable for application integration, while validating
prediction, risk scoring, explainability, and inference performance.

------------------------------------------------------------------------

## 1. Phase 5 Objective

Phase 5 converts the validated Phase 4 model into a reusable
URL-analysis engine.

The production inference flow is:

``` text
URL
 ↓
URL Feature Extraction
 ↓
25 Model Features
 ↓
XGBoost Model
 ↓
Isotonic Probability Calibration
 ↓
Calibrated Phishing Probability
 ↓
Risk Score (0–100)
 ↓
Risk Level
 ↓
Prediction + Security Decision + Reasons
```

No model retraining is performed in Phase 5.

------------------------------------------------------------------------

## 2. Phase 4 Model Used

Phase 5 uses the model selected and calibrated in Phase 4:

-   **Model:** XGBoost
-   **Calibration:** Isotonic probability calibration
-   **Phishing decision threshold:** 0.15
-   **Risk score:** `round(calibrated_phishing_probability × 100)`

The threshold was selected using validation data only and was not tuned
using the final test or unseen-domain test sets.

### Official Phase 4 Evaluation

  Metric            Test   Unseen-Domain Test
  ------------- -------- --------------------
  F1              0.7698               0.7385
  Precision       0.6681               0.6489
  Recall          0.9081               0.8569
  FPR             0.0540               0.0421
  FNR             0.0919               0.1431
  ROC-AUC         0.9812               0.9766
  PR-AUC          0.9165               0.8696
  Brier Score     0.0246               0.0251

These remain the official Phase 4 evaluation results. The Phase 5 sample
validation is a deployment/inference sanity check, not a replacement for
the official evaluation.

------------------------------------------------------------------------

## 3. Feature Pipeline

The Phase 5 inference engine reproduces the same 25 features used by the
Phase 3/Phase 4 model:

1.  `url_length`
2.  `domain_length`
3.  `subdomain_count`
4.  `path_length`
5.  `query_length`
6.  `has_ip`
7.  `has_https`
8.  `has_at`
9.  `has_dash`
10. `has_multiple_subdomains`
11. `special_char_count`
12. `digit_count`
13. `entropy`
14. `has_shortener`
15. `suspicious_keyword_count`
16. `dot_count`
17. `slash_count`
18. `hyphen_count`
19. `percent_encoded_count`
20. `query_parameter_count`
21. `uppercase_count`
22. `domain_digit_count`
23. `domain_entropy`
24. `path_segment_count`
25. `digit_ratio`

The inference engine uses URL-derived information only. It does not
perform DNS, WHOIS, webpage-content, or external network lookups.

------------------------------------------------------------------------

## 4. Risk Engine

The calibrated probability is converted to a 0--100 risk score:

``` text
risk_score = round(calibrated_phishing_probability × 100)
```

Risk bands:

      Score Risk Level
  --------- ------------
      0--25 SAFE
     26--50 LOW RISK
     51--75 SUSPICIOUS
    76--100 HIGH RISK

The ML prediction threshold and risk bands are intentionally separate.

### Security Decision Mapping

  Risk Level   Application Decision
  ------------ ----------------------
  SAFE         ALLOW
  LOW RISK     REVIEW
  SUSPICIOUS   WARN
  HIGH RISK    BLOCK

This separation prevents the probability threshold from being confused
with the user-facing risk category.

------------------------------------------------------------------------

## 5. Explainability

Phase 5 adds human-readable URL-level reasons based on observed URL
characteristics.

Examples include:

-   IP address used instead of a normal domain
-   Suspicious security/account-related keyword detected
-   Multiple subdomains detected
-   URL uses a known URL-shortening service
-   URL contains `@`
-   Percent-encoded characters detected
-   High proportion of digits in URL
-   Unusually long URL
-   Many query parameters detected

These are **rule-based explanations of observed URL characteristics**.
They are not presented as exact model feature contributions.

A Phase 5.1 correction was also made so that an IP address is not
incorrectly described as having multiple subdomains.

------------------------------------------------------------------------

## 6. Manual Inference Tests

The inference engine was tested with representative URLs.

### Test 1 --- `https://example.com/login`

``` text
Phishing probability: 0.998925
Risk score:            100
Risk level:            HIGH RISK
Prediction:            PHISHING
Threshold:             0.15
```

Observed reason:

``` text
Suspicious security/account-related keyword detected
```

### Test 2 --- `https://www.youtube.com/`

``` text
Phishing probability: 0.461707
Risk score:            46
Risk level:            LOW RISK
Prediction:            PHISHING
Threshold:             0.15
```

This demonstrates an important design distinction: a URL can fall into
the LOW RISK probability band while still exceeding the frozen ML
decision threshold of 0.15.

The application therefore uses `REVIEW` as the user-facing action for
LOW RISK.

### Test 3 --- `https://www.google.com`

``` text
Phishing probability: 0.011523
Risk score:            1
Risk level:            SAFE
Prediction:            BENIGN
```

### Test 4 --- `https://www.microsoft.com`

``` text
Phishing probability: 0.031220
Risk score:            3
Risk level:            SAFE
Prediction:            BENIGN
```

### Test 5 --- IP-based login URL

``` text
http://192.168.1.10/login/verify/account
```

Result:

``` text
Phishing probability: 1.000000
Risk score:            100
Risk level:            HIGH RISK
Prediction:            PHISHING
```

Observed indicators included:

-   IP address instead of a normal domain
-   Suspicious security/account-related keywords

------------------------------------------------------------------------

## 7. Phase 5.2 Validation

To avoid unnecessarily rerunning inference over more than 150,000 URLs
in each evaluation split, a representative stratified sample of 1,000
rows was used from each dataset.

### Test Sample

  Metric                       Result
  ----------------- -----------------
  Rows                          1,000
  Accuracy                     0.9250
  F1                           0.7253
  Precision                    0.5964
  Recall                       0.9252
  ROC-AUC                      0.9817
  Runtime                8.10 seconds
  Average latency         8.10 ms/URL
  Throughput          123.44 URLs/sec

### Unseen-Domain Sample

  Metric                       Result
  ----------------- -----------------
  Rows                          1,000
  Accuracy                     0.9390
  F1                           0.6995
  Precision                    0.5917
  Recall                       0.8554
  ROC-AUC                      0.9770
  Runtime                8.35 seconds
  Average latency         8.35 ms/URL
  Throughput          119.78 URLs/sec

------------------------------------------------------------------------

## 8. Consistency Checks

The Phase 5.2 validation performed two important internal consistency
checks.

### Risk Score Consistency

The calculated risk score was verified against:

``` text
round(probability × 100)
```

Result:

``` text
TEST SAMPLE:             PASS
UNSEEN-DOMAIN SAMPLE:    PASS
```

### Risk Level Consistency

The calculated risk level was verified against the defined risk bands.

Result:

``` text
TEST SAMPLE:             PASS
UNSEEN-DOMAIN SAMPLE:    PASS
```

Therefore, the probability → score → risk-level pipeline is internally
consistent.

------------------------------------------------------------------------

## 9. Performance Analysis

Measured single-URL inference performance was approximately:

``` text
8.10–8.35 ms per URL
≈ 120 URLs per second
```

This is suitable for a desktop JavaFX application where URL analysis
should complete quickly enough for interactive use.

The measured time includes feature extraction and model inference in the
Phase 5 validation loop.

------------------------------------------------------------------------

## 10. Data Leakage and Evaluation Discipline

Phase 5 follows the evaluation discipline established in earlier phases:

-   `source` is provenance information and is not used as an ML feature.
-   `domain` is used for grouping/splitting and is not used as a raw ML
    feature.
-   Test data is not used to tune the model.
-   Unseen-domain data is not used for feature selection or threshold
    tuning.
-   The Phase 4 threshold of 0.15 remains frozen.
-   Phase 5 does not retrain the model.
-   The Phase 5 validation sample is used only to verify
    deployment/inference behavior.

------------------------------------------------------------------------

## 11. Phase 5 Deliverables

### Scripts

``` text
phase5_inference.py
phase5_validation.py
```

### Generated validation outputs

``` text
data/phase5/validation_test_sample.csv
data/phase5/validation_unseen_sample.csv
data/phase5/phase5_validation_report.txt
```

### Primary model dependency

``` text
data/phase4/xgboost_calibrated.joblib
```

The exact model artifact path should be verified against the actual
Phase 4 output directory before final deployment.

------------------------------------------------------------------------

## 12. Phase 5 Architecture

``` text
                    ┌─────────────────────┐
                    │       URL Input     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Feature Extraction  │
                    │      25 features    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      XGBoost        │
                    │  Phase 4 candidate  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Isotonic Calibration│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Phishing Probability│
                    └──────────┬──────────┘
                               │
                  ┌────────────┴────────────┐
                  ▼                         ▼
        ┌──────────────────┐       ┌──────────────────┐
        │ ML Threshold 0.15│       │ Risk Score 0–100 │
        └────────┬─────────┘       └────────┬─────────┘
                 │                          │
                 ▼                          ▼
        BENIGN / PHISHING          SAFE / LOW / SUSPICIOUS /
                                   HIGH RISK
                 │                          │
                 └────────────┬─────────────┘
                              ▼
                    ┌─────────────────────┐
                    │ Security Decision   │
                    │ ALLOW / REVIEW /    │
                    │ WARN / BLOCK        │
                    └─────────────────────┘
```

------------------------------------------------------------------------

## 13. Limitations

1.  The model is URL-based and does not inspect webpage content.
2.  No temporal evaluation is currently available because the master
    dataset does not contain reliable timestamps.
3.  The Phase 5.2 validation uses 1,000-row samples rather than the
    complete test datasets.
4.  Rule-based explanations describe URL indicators and should not be
    interpreted as exact model attribution.
5.  A legitimate URL can receive a non-zero or elevated phishing
    probability because the model learns statistical patterns rather
    than website ownership or reputation.
6.  Risk decisions should therefore be treated as security assistance
    rather than absolute proof of maliciousness.

------------------------------------------------------------------------

## 14. Final Phase 5 Assessment

**PHASE 5 STATUS: PASS**

The AI WatchDog inference layer successfully:

-   Loads the calibrated Phase 4 model.
-   Recreates the required 25 URL features.
-   Produces calibrated phishing probabilities.
-   Applies the frozen 0.15 ML decision threshold.
-   Converts probabilities into 0--100 risk scores.
-   Assigns consistent risk levels.
-   Provides human-readable URL-level indicators.
-   Produces consistent results on unseen-domain samples.
-   Achieves approximately 120 URLs/second in the validation
    environment.
-   Provides a reusable interface suitable for JavaFX integration.

### Final ML-to-Application Pipeline

``` text
Phase 1
Dataset Construction & Analysis
        ↓
Phase 2
Feature Engineering
        ↓
Phase 3
Baseline Model Comparison
        ↓
Phase 4
Calibration & Threshold Optimization
        ↓
Phase 5
Production Inference & Validation
        ↓
Phase 6
JavaFX Application Integration
```

**Next recommended phase: Phase 6 --- JavaFX integration and final
application workflow.**
