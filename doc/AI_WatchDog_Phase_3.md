# AI WatchDog --- Phase 3: Baseline Model Training & Benchmarking

## 1. Phase Objective

Phase 3 establishes the machine-learning baseline for AI WatchDog.

The objective is to train and compare four classification models for
binary URL classification:

1.  **Logistic Regression** --- linear baseline
2.  **Random Forest** --- explainable tree baseline
3.  **XGBoost** --- gradient-boosting benchmark
4.  **LightGBM** --- lightweight desktop-deployment candidate

The purpose is not only to maximize classification performance, but also
to understand the trade-off between detection quality, generalization,
model size, and inference speed.

------------------------------------------------------------------------

## 2. Dataset Used

Phase 3 uses the domain-aware splits produced during Phase 1.5.

  Split                       Rows
  -------------------- -----------
  Training               1,043,526
  Validation               148,086
  Test                     150,409
  Unseen-domain test       138,869

The master dataset contains two labels:

-   `benign`
-   `phishing`

The data is highly imbalanced toward benign URLs, so accuracy alone is
not an appropriate primary metric.

### Data leakage controls

-   `source` is provenance information and is **not** used as an ML
    feature.
-   `domain` is used for grouping/splitting and is **not** used as a raw
    ML feature.
-   Test data is kept separate from model selection.
-   Unseen-domain data is reserved for generalization evaluation.
-   Threshold tuning is not performed using test or unseen-domain data.

------------------------------------------------------------------------

## 3. Feature Set

Phase 3 uses 25 numerical URL features selected from the Phase 2
feature-engineering stage.

### Original features

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

### Engineered features

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

These features are derived from URL lexical and structural
characteristics. No webpage content, DNS lookup, WHOIS query, or
external network request is required for inference.

------------------------------------------------------------------------

## 4. Models

### 4.1 Logistic Regression

Logistic Regression provides the simplest machine-learning baseline.

It is useful for determining how much predictive value can be obtained
from a linear decision boundary.

**Advantages** - Very small model - Extremely fast inference - Easy to
explain

**Limitations** - Cannot naturally model complex nonlinear feature
interactions - Significantly weaker predictive performance in this
experiment

------------------------------------------------------------------------

### 4.2 Random Forest

Random Forest is the explainable tree-based baseline.

It can capture nonlinear relationships between URL characteristics and
phishing behavior and provides native feature importance.

**Advantages** - Strong predictive performance - Nonlinear decision
boundaries - Easy to inspect feature importance - Good phishing recall

**Limitations** - Large serialized model - Higher inference latency than
boosting models in this experiment

------------------------------------------------------------------------

### 4.3 XGBoost

XGBoost is the main gradient-boosting benchmark.

It provides strong nonlinear modeling while maintaining a relatively
small serialized model.

**Advantages** - Strong ROC-AUC and PR-AUC - Small model footprint -
Very fast inference - Good fit for CPU-based deployment

**Limitations** - Slightly lower F1 than Random Forest at the baseline
threshold - Requires probability/threshold calibration before production
use

------------------------------------------------------------------------

### 4.4 LightGBM

LightGBM is evaluated as the lightweight desktop deployment candidate.

**Advantages** - Very small model - Fast CPU inference - Efficient
gradient boosting

**Limitations** - Lower F1 and PR-AUC than XGBoost in the current
experiment

------------------------------------------------------------------------

## 5. Baseline Threshold

All Phase 3 binary classification results use:

``` text
threshold = 0.50
```

This threshold is only a **baseline operating point**.

It is not considered the final production threshold.

The final threshold must be selected using validation data in Phase 4.

------------------------------------------------------------------------

# 6. Phase 3 Results

## Validation

  -----------------------------------------------------------------------------
  Model                  F1    Precision       Recall      ROC-AUC       PR-AUC
  ------------ ------------ ------------ ------------ ------------ ------------
  **Random       **0.7749**   **0.6739**       0.9115       0.9826       0.9220
  Forest**                                                         

  XGBoost            0.7466       0.6208   **0.9364**   **0.9841**   **0.9322**

  LightGBM           0.7330       0.6050       0.9296       0.9823       0.9171

  Logistic           0.4621       0.3697       0.6161       0.8956       0.5598
  Regression                                                       
  -----------------------------------------------------------------------------

### Validation interpretation

Random Forest achieves the highest F1 at the baseline threshold.

XGBoost, however, achieves the highest ROC-AUC and PR-AUC, indicating
strong probability ranking performance.

Therefore, F1 alone should not determine the final production model.

------------------------------------------------------------------------

# 7. Final Test Results

The test set is used only for final evaluation after model selection.

  Metric                    Result
  ---------------- ---------------
  Selected model     Random Forest
  F1                    **0.7559**
  Precision                 0.6424
  Recall                    0.9181
  ROC-AUC                   0.9805
  PR-AUC                    0.9155

The model retains strong phishing detection capability on the held-out
test set.

------------------------------------------------------------------------

# 8. Unseen-Domain Evaluation

The unseen-domain test evaluates generalization to domains that were not
available to the training/validation process.

  Metric            Result
  ----------- ------------
  F1            **0.7291**
  Precision         0.6257
  Recall            0.8734
  ROC-AUC           0.9767
  PR-AUC            0.8710
  FPR               0.0474
  FNR               0.1266

The decrease from test F1 to unseen-domain F1 is:

``` text
0.7559 - 0.7291 = 0.0268
```

The ROC-AUC gap is:

``` text
0.9805 - 0.9767 = 0.0038
```

These relatively small gaps indicate good domain-level generalization.

------------------------------------------------------------------------

# 9. Phase 3.5 Deployment Benchmark

Phase 3.5 evaluates the already-trained models without retraining.

The benchmark adds:

-   False Positive Rate (FPR)
-   False Negative Rate (FNR)
-   Single-URL inference latency
-   P50 latency
-   P95 latency
-   P99 latency
-   Throughput
-   Serialized model size

## Deployment comparison

  ---------------------------------------------------------------------------------------
  Model               Val F1      Test F1    Unseen F1   Unseen FPR        P95       Size
                                                                       latency 
  ------------- ------------ ------------ ------------ ------------ ---------- ----------
  **Random        **0.7749**   **0.7559**   **0.7291**   **0.0474**   52.89 ms  416.33 MB
  Forest**                                                                     

  **XGBoost**         0.7466       0.7147       0.6876       0.0665     **1.92     **4.83
                                                                          ms**       MB**

  LightGBM            0.7330       0.7001       0.6714       0.0706    2.14 ms     **3.32
                                                                                     MB**

  Logistic            0.4621       0.4373       0.4990       0.1175     **0.24     \~0 MB
  Regression                                                              ms** 
  ---------------------------------------------------------------------------------------

------------------------------------------------------------------------

# 10. Deployment Analysis

## Random Forest

Random Forest is the strongest model by F1 and has the lowest
unseen-domain FPR among the four models.

However:

``` text
Model size = 416.33 MB
P95 latency = 52.89 ms
```

This is a significant disadvantage for a lightweight desktop security
application.

------------------------------------------------------------------------

## XGBoost

XGBoost provides the strongest balance between detection quality and
deployment efficiency.

Key results:

``` text
Unseen F1       = 0.6876
Unseen ROC-AUC  = 0.9775
Unseen PR-AUC   = 0.8830
P95 latency     = 1.92 ms
Model size      = 4.83 MB
```

Compared with Random Forest, XGBoost has a dramatically smaller model
footprint and much lower inference latency.

Its unseen-domain ROC-AUC and PR-AUC are also strong.

Therefore:

> **XGBoost is the current primary deployment candidate, pending Phase 4
> calibration and threshold optimization.**

------------------------------------------------------------------------

## LightGBM

LightGBM has the smallest boosting model:

``` text
3.32 MB
```

However, XGBoost performs better on F1, ROC-AUC, PR-AUC, unseen-domain
F1, and unseen-domain FPR in the current benchmark.

The small model-size advantage of LightGBM does not currently compensate
for its lower predictive performance.

------------------------------------------------------------------------

## Logistic Regression

Logistic Regression is extremely efficient:

``` text
P95 latency = 0.242 ms
```

but its predictive performance is substantially lower.

It remains useful as the linear reference baseline rather than as the
primary production model.

------------------------------------------------------------------------

# 11. Model Selection Decision

The Phase 3 results support two different conclusions.

### Best predictive model at threshold 0.50

**Random Forest**

Reason:

``` text
Validation F1 = 0.7749
Test F1       = 0.7559
Unseen F1     = 0.7291
```

### Best current desktop deployment candidate

**XGBoost**

Reason:

``` text
Model size     = 4.83 MB
P95 latency    = 1.92 ms
Unseen ROC-AUC = 0.9775
Unseen PR-AUC  = 0.8830
```

This distinction is important because AI WatchDog is intended to operate
as a lightweight, real-time desktop security system.

The final deployment choice should therefore not be based on F1 alone.

------------------------------------------------------------------------

# 12. Scientific Interpretation

The experiment demonstrates that nonlinear tree-based models are
substantially more effective than the linear baseline for this URL
classification task.

Random Forest produces the highest F1 at the default threshold, while
XGBoost produces the strongest ranking metrics among the tested models.

The strong unseen-domain ROC-AUC values demonstrate that the models
retain useful discrimination when evaluated on domains not seen during
training/validation.

The deployment benchmark further shows a major practical trade-off:

``` text
Random Forest
High predictive performance
        +
Large model / slower inference

XGBoost
Slightly lower baseline F1
        +
Very small model / very fast inference
```

This trade-off is central to selecting a practical model for AI
WatchDog.

------------------------------------------------------------------------

# 13. Limitations

Phase 3 has several limitations that must be addressed before production
deployment.

### 13.1 Baseline threshold

The 0.50 threshold is arbitrary as a baseline operating point.

It should not be treated as the final phishing decision threshold.

### 13.2 Probability calibration

Raw model probabilities have not yet been calibrated.

A calibrated probability is required before converting model output into
a meaningful risk score.

### 13.3 Temporal evaluation

The current master dataset does not contain a reliable
timestamp/collection-date field.

Therefore, a temporal test set has not yet been generated.

### 13.4 Model deployment benchmark

The latency benchmark measures model inference and does not represent
total end-to-end application latency, which will also include URL
parsing, feature extraction, API communication, and UI processing.

------------------------------------------------------------------------

# 14. Phase 3 Conclusion

Phase 3 successfully established a four-model machine-learning
benchmark.

**Random Forest** is the strongest model according to baseline F1 and
unseen-domain F1.

**XGBoost** provides the best current balance between predictive
capability and desktop deployment requirements, with a 4.83 MB model and
approximately 1.92 ms P95 single-URL inference latency.

**LightGBM** is extremely compact but currently underperforms XGBoost.

**Logistic Regression** provides a useful linear baseline but is not
competitive with the nonlinear models.

The current recommended production candidate is therefore:

> **XGBoost --- pending Phase 4 calibration and threshold
> optimization.**

------------------------------------------------------------------------

# 15. Next Phase

## Phase 4 --- Probability Calibration & Threshold Optimization

Phase 4 will use the validation set to:

1.  Calibrate model probabilities.
2.  Sweep classification thresholds.
3.  Measure precision, recall, F1, FPR, and FNR across thresholds.
4.  Select an operating threshold appropriate for phishing detection.
5.  Evaluate the selected threshold on the untouched test set.
6.  Evaluate generalization on the unseen-domain test set.
7.  Convert calibrated probability into the AI WatchDog 0--100 risk
    score.
8.  Define the final risk bands:

    Risk Score Decision
  ------------ ------------
         0--25 SAFE
        26--50 LOW RISK
        51--75 SUSPICIOUS
       76--100 HIGH RISK

The risk threshold and bands must be frozen only after validation-based
optimization and then evaluated on the held-out test and unseen-domain
datasets.

------------------------------------------------------------------------

## Phase 3 Deliverables

Expected project artifacts:

``` text
phase3_baseline_models.py
phase3_5_deployment_benchmark.py

data/
├── phase3/
│   └── models/
│       ├── logistic_regression.joblib
│       ├── random_forest.joblib
│       ├── xgboost.joblib
│       └── lightgbm.joblib
│
└── phase3_5/
    ├── deployment_benchmark.csv
    ├── feature_importance.csv
    └── deployment_benchmark_report.txt
```

------------------------------------------------------------------------

## Reproducibility Notes

-   Random seeds should remain fixed.
-   The same 25-feature schema must be used for every model.
-   `source` and raw `domain` must not be used as model inputs.
-   Test and unseen-domain datasets must remain untouched during model
    selection and threshold optimization.
-   Any future change to feature engineering should trigger a new
    controlled experiment.
