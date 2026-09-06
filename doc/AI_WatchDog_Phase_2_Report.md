# AI WatchDog — Phase 2 Feature Engineering Report

## 1. Objective

Phase 2 evaluates the URL-based feature set for the AI WatchDog phishing-detection system.

The analysis covers:

- Feature engineering
- Feature distribution
- Benign vs phishing separation
- Feature importance
- Feature correlation
- Security-related indicators
- Redundancy identification
- Data-leakage precautions
- Candidate feature selection for Phase 3

---

## 2. Dataset Used

Feature analysis was performed on the **training split only** to avoid using validation/test information during feature selection.

| Metric | Value |
|---|---:|
| Training rows | 1,043,526 |
| Original engineered feature set | 15 |
| Additional engineered features | 31 |
| Total candidate numeric features | 46 |

The validation, test, and unseen-domain datasets are reserved for later model evaluation.

---

## 3. Original Feature Set

The original URL feature set contains:

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
```

The raw fields below are retained for data management and analysis but should not be used directly as model predictors in the baseline:

```text
url
domain
source
label
tld
```

### Data-science rules

- `label` is the target variable.
- `source` is provenance information and must not be used as an ML predictor.
- `domain` is required for domain-aware splitting but should not be used as a raw ML predictor.
- `url` is retained for prediction/audit purposes but is not directly used by the first numerical baseline models.
- `tld` can be considered separately later if an encoded version is scientifically justified.

---

# 4. Additional Engineered Features

31 additional features were generated from the URL and domain structure.

### URL character/count features

```text
dot_count
slash_count
hyphen_count
underscore_count
percent_encoded_count
double_slash_count
colon_count
semicolon_count
equals_count
ampersand_count
question_mark_count
at_count
uppercase_count
lowercase_count
letter_count
url_digit_count
url_special_count
```

### Domain features

```text
domain_digit_count
domain_hyphen_count
domain_dot_count
domain_special_count
domain_entropy
```

### Ratio/count features

```text
digit_ratio
special_char_ratio
letter_ratio
path_segment_count
query_parameter_count
```

### Binary indicators

```text
has_percent_encoding
has_many_digits
has_long_url
has_long_domain
```

These features are candidate features only. They are not automatically considered part of the final model.

---

# 5. ExtraTrees Feature Importance

An ExtraTrees classifier was used as a **feature-screening tool**, not as the final AI WatchDog model.

## Top 15 Features

| Rank | Feature | Importance |
|---:|---|---:|
| 1 | `has_https` | 0.121471 |
| 2 | `slash_count` | 0.074508 |
| 3 | `subdomain_count` | 0.067827 |
| 4 | `domain_dot_count` | 0.054174 |
| 5 | `dot_count` | 0.048693 |
| 6 | `has_many_digits` | 0.046341 |
| 7 | `path_length` | 0.045215 |
| 8 | `special_char_count` | 0.039328 |
| 9 | `entropy` | 0.038113 |
| 10 | `has_long_domain` | 0.036095 |
| 11 | `url_special_count` | 0.032729 |
| 12 | `url_length` | 0.030081 |
| 13 | `domain_length` | 0.029911 |
| 14 | `lowercase_count` | 0.027121 |
| 15 | `digit_ratio` | 0.023914 |

### Interpretation

URL structure and complexity are strong signals in this dataset.

The leading features indicate that the model can obtain useful information from:

- HTTPS presence
- Number of URL path separators
- Number of subdomains
- Domain structure
- URL/domain length
- Digit patterns
- Character complexity
- Entropy

`has_https` is the strongest individual ExtraTrees feature.

However, high feature importance does **not** mean that HTTPS itself is a reliable phishing indicator. HTTPS is common on legitimate websites as well. Its importance must therefore be validated on the held-out and unseen-domain datasets.

---

# 6. Benign vs Phishing Feature Separation

The following features produced the largest standardized differences between benign and phishing URLs.

| Rank | Feature | Standardized Difference |
|---:|---|---:|
| 1 | `entropy` | 0.7528 |
| 2 | `domain_dot_count` | 0.7018 |
| 3 | `subdomain_count` | 0.6515 |
| 4 | `dot_count` | 0.6148 |
| 5 | `slash_count` | 0.5758 |
| 6 | `lowercase_count` | 0.5037 |
| 7 | `domain_length` | 0.4800 |
| 8 | `digit_ratio` | 0.4659 |
| 9 | `url_length` | 0.4601 |
| 10 | `url_special_count` | 0.4554 |
| 11 | `special_char_count` | 0.4554 |
| 12 | `letter_count` | 0.4478 |
| 13 | `has_many_digits` | 0.4332 |
| 14 | `path_length` | 0.4076 |
| 15 | `path_segment_count` | 0.4035 |

### Interpretation

The results suggest that **URL structural complexity** is more informative than relying only on suspicious words.

Entropy, domain structure, subdomains, path complexity, and character composition are particularly promising.

This supports the project's approach of combining multiple lightweight URL characteristics rather than building a detector based solely on keyword matching.

---

# 7. Correlation Analysis

Features with an absolute Pearson correlation of at least 0.90 were flagged.

| Feature 1 | Feature 2 | Correlation |
|---|---|---:|
| `special_char_count` | `url_special_count` | 1.0000 |
| `digit_count` | `url_digit_count` | 1.0000 |
| `url_length` | `letter_count` | 0.9844 |
| `subdomain_count` | `domain_dot_count` | 0.9755 |
| `lowercase_count` | `letter_count` | 0.9600 |
| `has_at` | `at_count` | 0.9600 |
| `equals_count` | `query_parameter_count` | 0.9525 |
| `slash_count` | `path_segment_count` | 0.9473 |
| `ampersand_count` | `query_parameter_count` | 0.9395 |
| `url_length` | `lowercase_count` | 0.9398 |
| `url_length` | `url_special_count` | 0.9127 |
| `url_length` | `special_char_count` | 0.9127 |

## Decision

Several redundant features should not be retained together unnecessarily.

Examples:

```text
special_char_count ↔ url_special_count
digit_count ↔ url_digit_count
has_at ↔ at_count
subdomain_count ↔ domain_dot_count
slash_count ↔ path_segment_count
```

The final feature set should prefer the more interpretable representation.

---

# 8. Recommended Phase-3 Baseline Feature Set

Based on Phase 2, the recommended initial feature set is approximately 25 features.

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

## Features intentionally excluded from the initial baseline

```text
url_digit_count
url_special_count
letter_count
lowercase_count
at_count
domain_dot_count
```

These are excluded primarily because they are highly correlated with retained features.

This is a **baseline candidate set**, not yet the final feature set.

---

# 9. Important Feature: `has_https`

`has_https` has the highest ExtraTrees importance:

```text
0.121471
```

This requires careful interpretation.

### Do not assume:

```text
HTTPS = phishing
```

or:

```text
HTTP = benign
```

Both assumptions are incorrect.

HTTPS is widely used by legitimate websites. Its high importance may partly reflect characteristics of the source datasets.

Therefore:

> `has_https` should remain in the candidate set and be tested empirically during Phase 3.

If its performance deteriorates substantially on the unseen-domain test, its contribution should be reconsidered.

---

# 10. Leakage Prevention

The following rules apply to the remaining project stages.

### `source`

Must not be used as an ML predictor.

Reason:

Different sources have different collection/classification mechanisms. Using source can allow the model to learn dataset-specific artifacts instead of phishing characteristics.

### `domain`

Must be used for grouping and domain-aware splitting.

It should not be supplied as a raw categorical feature to the baseline model.

### `label`

Must never appear among predictors.

### Test sets

The following datasets must remain untouched during feature selection:

```text
test.csv
unseen_domain_test.csv
```

They are reserved for final evaluation.

---

# 11. Class Imbalance

The master dataset contains approximately:

```text
Benign:    90.81%
Phishing:   9.19%
```

This distribution should be preserved.

The master dataset should **not** be artificially converted into a 50/50 dataset.

Class imbalance can instead be handled during model training using techniques such as:

- class weighting
- threshold optimization
- controlled resampling where justified

Evaluation must use metrics beyond accuracy.

---

# 12. Current Phase-2 Assessment

| Area | Assessment |
|---|---|
| Feature engineering | Good |
| Candidate feature count | 46 |
| Feature redundancy | Present |
| Strong discriminative features | Identified |
| Feature leakage | No obvious leakage detected |
| Source leakage risk | Must be controlled |
| Class distribution | Acceptable |
| Final feature set | Candidate only |
| Ready for baseline modeling | **Yes** |

---

# 13. Phase-2 Conclusion

Phase 2 successfully identified a compact, interpretable set of URL-based features.

The analysis shows that:

1. URL structural complexity is informative.
2. Entropy is one of the strongest class-separating features.
3. Domain/subdomain structure is highly informative.
4. Several engineered features are redundant.
5. `source` must remain excluded from ML predictors.
6. The natural 90.81/9.19 class distribution should be preserved.
7. The recommended ~25-feature set is suitable for baseline modeling.
8. Final feature selection must be based on validation performance rather than ExtraTrees importance alone.

---

# 14. Next Phase — Phase 3

The next stage is **Baseline Model Training and Evaluation**.

The initial models should include:

```text
1. Logistic Regression
2. Random Forest
3. ExtraTrees
4. XGBoost or LightGBM
```

Each model should be evaluated using:

```text
Precision
Recall
F1-score
ROC-AUC
PR-AUC
Confusion Matrix
False Positive Rate
False Negative Rate
```

The final comparison should include both:

```text
test.csv
```

and, most importantly:

```text
unseen_domain_test.csv
```

The model should not be selected solely because it has the highest random-test accuracy.

For AI WatchDog, **phishing recall, false-positive control, probability quality, and unseen-domain generalization** are key considerations.

---

## Phase 2 Status

**COMPLETE ✅**

**Recommended next step: Phase 3 — Baseline Model Training.**
