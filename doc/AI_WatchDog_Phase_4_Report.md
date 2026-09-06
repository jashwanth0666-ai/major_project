# AI WatchDog — Phase 4 Report

## Probability Calibration, Threshold Optimization & Risk Engine

---

## 1. Executive Summary

Phase 4 converts the Phase 3 XGBoost deployment candidate into a calibrated phishing-risk model suitable for the AI WatchDog inference layer.

The phase performs three main tasks:

1. Train the XGBoost deployment candidate using the domain-aware training split.
2. Calibrate phishing probabilities using **isotonic regression**.
3. Select an operating classification threshold using validation data only, then evaluate the frozen configuration on the untouched test and unseen-domain test sets.

The selected operating threshold is:

> **0.15**

The threshold was selected using the rule:

> **Maximize F1 subject to recall ≥ 0.90**

The resulting model achieved:

- **Test F1 = 0.7698**
- **Test Precision = 0.6681**
- **Test Recall = 0.9081**
- **Test ROC-AUC = 0.9812**
- **Test PR-AUC = 0.9165**
- **Unseen-domain F1 = 0.7385**
- **Unseen-domain Precision = 0.6489**
- **Unseen-domain Recall = 0.8569**
- **Unseen-domain ROC-AUC = 0.9766**
- **Unseen-domain PR-AUC = 0.8696**

These results make calibrated XGBoost the current strongest deployment candidate for AI WatchDog.

---

## 2. Phase 4 Objective

The objective of Phase 4 is to move beyond raw model classification and produce a deployment-ready probability and risk system.

Phase 3 established baseline predictive performance. Phase 4 addresses:

- probability calibration,
- operating-threshold selection,
- phishing detection performance,
- false-positive/false-negative trade-offs,
- unseen-domain generalization,
- and conversion of model probability into a user-facing risk score.

The test and unseen-domain datasets remain strictly held out during calibration and threshold selection.

---

## 3. Input Dataset

The existing domain-aware splits from Phase 1.5 were used.

| Dataset | Rows | Phishing | Benign |
|---|---:|---:|---:|
| Training | 1,043,526 | 92,725 | 950,801 |
| Validation | 148,086 | 15,748 | 132,338 |
| Test | 150,409 | 16,076 | 134,333 |
| Unseen-domain test | 138,869 | 11,552 | 127,317 |

The Phase 3 feature set was retained.

### Validation split

The 148,086-row validation set was divided into two independent purposes:

| Purpose | Rows |
|---|---:|
| Calibration | 74,043 |
| Threshold selection | 74,043 |

This separation prevents the same validation observations from being used simultaneously to learn probability calibration and choose the final operating threshold.

---

## 4. Feature Set

The Phase 3 feature set of 25 numeric features was retained.

```text
url_length
domain_length
subdomain_count
path_length
query_length
has_ip
has_https
has_at
has_dash
has_multiple_subdomains
special_char_count
digit_count
entropy
has_shortener
suspicious_keyword_count
dot_count
slash_count
hyphen_count
percent_encoded_count
query_parameter_count
uppercase_count
domain_digit_count
domain_entropy
path_segment_count
digit_ratio
```

The following Phase 2 data-science rules remain in effect:

- `source` is provenance information and is not an ML feature.
- `domain` is used for grouping/splitting and is not used as a raw ML feature.
- Test and unseen-domain data are not used for feature selection or threshold tuning.

---

## 5. Model

### XGBoost

XGBoost was selected as the Phase 4 deployment candidate based on the Phase 3 model comparison.

The model was trained with the domain-aware training data and class weighting based on the training-set class ratio.

The resulting classifier produces a raw phishing probability which is subsequently calibrated.

---

## 6. Probability Calibration

### Method: Isotonic Regression

The XGBoost probabilities were calibrated using isotonic regression.

The calibration set contained:

```text
74,043 rows
```

Isotonic calibration was selected because the calibration dataset is sufficiently large to support a flexible monotonic mapping between raw model scores and empirical phishing probability.

The purpose of calibration is to make the predicted probability more meaningful as a risk estimate.

For example, after calibration:

```text
calibrated probability = 0.80
```

is intended to represent a substantially higher phishing risk than:

```text
calibrated probability = 0.20
```

The calibrated probabilities are used by the AI WatchDog Risk Engine.

---

## 7. Threshold Optimization

A classification threshold was evaluated over:

```text
0.05 to 0.95
```

using increments of:

```text
0.01
```

Threshold selection was performed exclusively on the threshold-selection portion of validation data.

### Selection rule

```text
Maximize F1
subject to Recall >= 0.90
```

This rule reflects the security-oriented goal of maintaining high phishing detection while controlling false positives.

### Selected threshold

```text
0.15
```

Therefore the current binary operating rule is:

```text
if calibrated_phishing_probability >= 0.15:
    prediction = PHISHING
else:
    prediction = BENIGN
```

The threshold was not selected using either the test set or unseen-domain test set.

---

## 8. Threshold-Selection Result

At the selected threshold of **0.15**, the threshold-selection data achieved:

| Metric | Result |
|---|---:|
| F1 | 0.7698* |
| Precision | 0.6681* |
| Recall | 0.9081* |
| FPR | 0.0540* |
| FNR | 0.0919* |

\*The values above are the final held-out test results and are included here as the deployment operating-point reference. The exact threshold-selection metrics are stored in `data/phase4/threshold_results.csv`.

---

## 9. Final Test Evaluation

After freezing the threshold at 0.15, the untouched test set was evaluated.

| Metric | Test |
|---|---:|
| F1 | **0.7698** |
| Precision | **0.6681** |
| Recall | **0.9081** |
| FPR | **0.0540** |
| FNR | **0.0919** |
| ROC-AUC | **0.9812** |
| PR-AUC | **0.9165** |
| Brier Score | **0.0246** |

### Interpretation

The model detects approximately 90.8% of phishing URLs in the held-out test set.

Precision of 66.8% means that roughly two-thirds of URLs classified as phishing are actually phishing.

The false-positive rate is approximately 5.4%, which is a useful improvement over a very aggressive high-recall operating point.

ROC-AUC of 0.9812 demonstrates excellent ranking/discrimination ability.

PR-AUC of 0.9165 is particularly important because the dataset is imbalanced toward benign URLs.

The Brier score of 0.0246 provides an additional measure of probabilistic prediction quality, with lower values being better.

---

## 10. Unseen-Domain Evaluation

The unseen-domain test contains domains not used in training, validation, or normal test grouping.

This provides a stronger test of generalization to previously unseen domains.

| Metric | Unseen-domain |
|---|---:|
| F1 | **0.7385** |
| Precision | **0.6489** |
| Recall | **0.8569** |
| FPR | **0.0421** |
| FNR | **0.1431** |
| ROC-AUC | **0.9766** |
| PR-AUC | **0.8696** |
| Brier Score | **0.0251** |

### Interpretation

The model maintains strong performance when evaluated on domains that were not present in the development data.

The unseen-domain F1 of **0.7385** demonstrates useful generalization.

Precision remains relatively strong at **0.6489**, while recall remains **0.8569**.

The unseen-domain false-positive rate is **4.21%**, lower than the test-set FPR of 5.40%.

The small difference between test ROC-AUC (0.9812) and unseen-domain ROC-AUC (0.9766) indicates that the model retains strong discrimination on unseen domains.

---

## 11. Phase 3 vs Phase 4

The Phase 3 selected Random Forest is compared against the Phase 4 calibrated XGBoost configuration.

| Metric | Phase 3 Random Forest | Phase 4 XGBoost | Change |
|---|---:|---:|---:|
| Test F1 | 0.7265 | **0.7698** | +0.0433 |
| Test Precision | 0.5955 | **0.6681** | +0.0726 |
| Test Recall | 0.9315 | 0.9081 | -0.0234 |
| Test ROC-AUC | 0.9804 | **0.9812** | +0.0008 |
| Test PR-AUC | 0.9145 | **0.9165** | +0.0020 |
| Unseen F1 | 0.7029 | **0.7385** | +0.0356 |
| Unseen Precision | 0.5790 | **0.6489** | +0.0699 |
| Unseen Recall | 0.8942 | 0.8569 | -0.0373 |
| Unseen ROC-AUC | 0.9767 | 0.9766 | -0.0001 |
| Unseen PR-AUC | 0.8697 | 0.8696 | -0.0001 |

### Conclusion from comparison

Phase 4 substantially improves F1 and precision while giving up a moderate amount of recall.

This is a favorable trade-off for a practical phishing-detection application because extremely aggressive recall can produce too many false alarms.

The unseen-domain F1 increases from **0.7029 to 0.7385**, indicating that the improvement is not limited to the ordinary test split.

---

## 12. Risk Engine

The calibrated probability is converted into a user-facing risk score.

### Formula

```text
risk_score = round(calibrated_phishing_probability * 100)
```

Therefore:

```text
probability 0.00 → risk score 0
probability 0.25 → risk score 25
probability 0.50 → risk score 50
probability 0.75 → risk score 75
probability 1.00 → risk score 100
```

### Risk bands

| Risk Score | Risk Level |
|---:|---|
| 0–25 | SAFE |
| 26–50 | LOW RISK |
| 51–75 | SUSPICIOUS |
| 76–100 | HIGH RISK |

The risk score is a continuous user-facing measure, while the 0.15 threshold is the binary classification operating point.

These two concepts should not be treated as identical.

---

## 13. Example Risk Outputs

### Example 1

```text
Phishing probability = 0.08
Risk score = 8
Risk level = SAFE
Binary prediction = BENIGN
```

### Example 2

```text
Phishing probability = 0.32
Risk score = 32
Risk level = LOW RISK
Binary prediction = PHISHING
```

### Example 3

```text
Phishing probability = 0.67
Risk score = 67
Risk level = SUSPICIOUS
Binary prediction = PHISHING
```

### Example 4

```text
Phishing probability = 0.94
Risk score = 94
Risk level = HIGH RISK
Binary prediction = PHISHING
```

The distinction is intentional: the binary threshold is optimized for detection performance, whereas the risk bands communicate severity to the user.

---

## 14. Data Leakage Controls

Phase 4 follows the project's leakage-prevention rules.

### Used for model training

```text
train.csv
```

### Used for probability calibration

```text
50% of validation.csv
```

### Used for threshold selection

```text
remaining 50% of validation.csv
```

### Used only for final evaluation

```text
test.csv
unseen_domain_test.csv
```

The test and unseen-domain datasets were not used to choose:

- model features,
- calibration parameters,
- classification threshold,
- or risk-engine operating threshold.

This preserves the validity of the final evaluation.

---

## 15. Generated Outputs

Phase 4 generates the following files:

```text
data/
└── phase4/
    ├── threshold_results.csv
    ├── calibration_results.csv
    ├── final_threshold_results.csv
    ├── xgboost_calibrated.joblib
    ├── risk_engine_config.json
    └── phase4_report.txt
```

### File purposes

**`threshold_results.csv`**

Contains performance metrics across the candidate threshold range.

**`calibration_results.csv`**

Contains probability-quality metrics including Brier score, ROC-AUC and PR-AUC.

**`final_threshold_results.csv`**

Contains final test and unseen-domain metrics at the frozen threshold.

**`xgboost_calibrated.joblib`**

Serialized calibrated XGBoost model for inference.

**`risk_engine_config.json`**

Stores the selected threshold, risk bands, formula and feature configuration.

**`phase4_report.txt`**

Human-readable Phase 4 experiment report.

---

## 16. Limitations

### No temporal evaluation

The master dataset currently contains no reliable timestamp/collection-date field.

Therefore a genuine temporal test set could not be produced.

The current evaluation measures:

- ordinary held-out generalization,
- and unseen-domain generalization.

It does not yet measure performance against future phishing campaigns.

### Dataset imbalance

The master dataset is approximately 90.81% benign and 9.19% phishing.

Therefore accuracy alone is not an adequate primary metric.

F1, precision, recall, PR-AUC and false-positive rate are more informative.

### Probability interpretation

Although isotonic calibration improves probability estimation, calibration quality should continue to be monitored when the model is exposed to future URL distributions.

---

## 17. Final Phase 4 Decision

### Selected model

> **XGBoost + isotonic probability calibration**

### Selected threshold

> **0.15**

### Binary decision rule

```text
P(phishing) >= 0.15 → PHISHING
P(phishing) <  0.15 → BENIGN
```

### Risk score

```text
round(P(phishing) * 100)
```

### Risk bands

```text
0–25    SAFE
26–50   LOW RISK
51–75   SUSPICIOUS
76–100  HIGH RISK
```

### Deployment recommendation

The Phase 4 configuration is the current **best ML deployment candidate** for AI WatchDog.

It improves both F1 and precision over the Phase 3 Random Forest baseline while retaining strong recall and excellent ROC-AUC/PR-AUC performance.

---

## 18. Next Phase

The next phase should focus on **production inference and application integration**, rather than another broad model-training experiment.

The intended pipeline is:

```text
User enters URL
      ↓
URL normalization
      ↓
Feature extraction
      ↓
25-feature vector
      ↓
Calibrated XGBoost
      ↓
Phishing probability
      ↓
Risk score 0–100
      ↓
Risk band
      ↓
Prediction + explanation
      ↓
JavaFX AI WatchDog interface
```

The final inference layer should expose a simple prediction interface that can be called by the JavaFX application.

---

## 19. Phase 4 Conclusion

Phase 4 successfully transformed the Phase 3 XGBoost candidate into a calibrated risk-scoring model.

The key result is:

```text
XGBoost
    +
Isotonic Calibration
    +
Threshold = 0.15
    ↓
Test F1 = 0.7698
Test Recall = 0.9081
Test Precision = 0.6681
Unseen F1 = 0.7385
Unseen Recall = 0.8569
Unseen Precision = 0.6489
```

The model is therefore ready to proceed to the **AI WatchDog inference/Risk Engine integration phase**.

---

**Phase 4 Status: COMPLETE**
