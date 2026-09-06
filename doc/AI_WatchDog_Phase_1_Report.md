# AI WatchDog --- Phase 1 Dataset Report

**Project:** AI WatchDog --- AI-Powered Phishing URL Detection & Risk
Scoring\
**Phase:** Phase 1 --- Dataset Collection, Cleaning, Labeling & Master
Dataset Creation\
**Dataset:** `phishing_master.csv`\
**Status:** Completed

------------------------------------------------------------------------

## 1. Executive Summary

The AI WatchDog Phase 1 dataset pipeline successfully combines multiple
URL sources into a single labeled master dataset for phishing URL
detection.

The final master dataset contains **1,480,890 unique URLs** across **20
columns**, including the target label, source information, URL/domain
metadata, and engineered lexical URL features.

The dataset contains:

-   **1,344,789 benign URLs (90.81%)**
-   **136,101 phishing URLs (9.19%)**
-   **0 duplicate URLs**
-   **474 domains with conflicting labels**
-   **12 URL-level label conflicts identified during master-dataset
    construction**

The dataset is suitable for the next stage of the project: **Phase 2 ---
feature analysis and feature engineering**, provided that the identified
label/domain conflicts are documented and handled carefully.

------------------------------------------------------------------------

## 2. Phase 1 Objectives

The objectives of Phase 1 were:

1.  Collect URL data from multiple sources.
2.  Normalize and clean URL records.
3.  Assign a binary classification label:
    -   `benign`
    -   `phishing`
4.  Remove duplicate URL records.
5.  Preserve dataset provenance using the `source` column.
6.  Extract lexical and structural URL features.
7.  Create a unified master dataset for machine-learning experiments.

------------------------------------------------------------------------

## 3. Data Sources

The master dataset was created by combining the following sources:

  Source                 Rows    Percentage
  ----------- --------------- -------------
  Tranco              999,989        67.53%
  `data`              406,748        27.47%
  PhishTank            73,855         4.99%
  OpenPhish               298         0.02%
  **Total**     **1,480,890**   **100.00%**

### Source interpretation

-   **Tranco:** primarily represents popular/legitimate domains and
    provides the major benign component.
-   **PhishTank:** provides known phishing URLs.
-   **OpenPhish:** provides additional phishing URLs.
-   **data:** the downloaded source dataset incorporated into the master
    dataset.

The `source` field is retained for **provenance and analysis**. It
should **not be used as an input feature during model training**,
because source information can introduce dataset-specific bias and
leakage.

------------------------------------------------------------------------

## 4. Master Dataset Construction

The initial combination produced:

  Processing Stage                      Rows
  -------------------------- ---------------
  Combined before cleaning         1,495,359
  After cleaning                   1,495,355
  Final master dataset         **1,480,890**

The final reduction includes duplicate/removal processing performed
during master-dataset construction.

The final dataset was saved as:

``` text
data/phishing_master.csv
```

------------------------------------------------------------------------

## 5. Label Distribution

The final binary classification distribution is:

  Label                 Count    Percentage
  ----------- --------------- -------------
  Benign            1,344,789        90.81%
  Phishing            136,101         9.19%
  **Total**     **1,480,890**   **100.00%**

### Class imbalance assessment

The dataset is naturally imbalanced, with benign URLs representing
approximately nine out of every ten records.

This imbalance should **not** be corrected by arbitrarily converting the
master dataset to a 50:50 distribution.

Instead, class imbalance should be handled during model development
using appropriate techniques such as:

-   class weighting,
-   threshold tuning,
-   controlled sampling where justified,
-   precision/recall-oriented evaluation,
-   PR-AUC and ROC-AUC.

The original master dataset should remain unchanged.

------------------------------------------------------------------------

## 6. Dataset Schema

The master dataset contains **20 columns**.

  -------------------------------------------------------------------------------------------
                     \# Column                       Description          ML Role
  --------------------- ---------------------------- -------------------- -------------------
                      1 `url`                        Original URL         Identifier/raw
                                                                          input

                      2 `label`                      Benign/phishing      **Target**
                                                     target               

                      3 `source`                     Dataset provenance   Metadata; exclude
                                                                          from model

                      4 `domain`                     Extracted domain     Grouping/analysis

                      5 `tld`                        Top-level domain     Feature candidate

                      6 `url_length`                 Total URL length     Feature

                      7 `domain_length`              Domain length        Feature

                      8 `subdomain_count`            Number of subdomains Feature

                      9 `path_length`                URL path length      Feature

                     10 `query_length`               Query-string length  Feature

                     11 `has_ip`                     Whether URL uses an  Feature
                                                     IP address           

                     12 `has_https`                  Whether HTTPS is     Feature
                                                     present              

                     13 `has_at`                     Presence of `@`      Feature

                     14 `has_dash`                   Presence of `-`      Feature

                     15 `has_multiple_subdomains`    Multiple-subdomain   Feature
                                                     indicator            

                     16 `special_char_count`         Number of special    Feature
                                                     characters           

                     17 `digit_count`                Number of digits     Feature

                     18 `entropy`                    URL character        Feature
                                                     entropy              

                     19 `has_shortener`              URL-shortener        Feature
                                                     indicator            

                     20 `suspicious_keyword_count`   Count of suspicious  Feature
                                                     keywords             
  -------------------------------------------------------------------------------------------

------------------------------------------------------------------------

## 7. Data Quality Results

### 7.1 Duplicate URLs

``` text
Duplicate URLs: 0
```

This is a strong result. Every URL in the final master dataset is
unique.

### 7.2 URL-level label conflicts

The master-dataset construction process identified:

``` text
Label conflicts: 12
```

These records should remain documented in a separate conflict file and
should be reviewed before final model training.

A conflicting URL should not be silently assigned an arbitrary label.

### 7.3 Domain-level label conflicts

Phase 1.5 identified:

``` text
Conflicting-label domains: 474
```

This means 474 domains contain URLs associated with both benign and
phishing labels.

This does **not automatically mean the records are incorrect**. A
legitimate domain can contain a malicious or compromised page, and
different data sources can also disagree.

Therefore, domain-level conflicts should be analyzed rather than
automatically deleted.

------------------------------------------------------------------------

## 8. Domain-Aware Dataset Splitting

To reduce domain leakage, the dataset was split at the **domain level**.

The resulting datasets are:

  Split                       Rows   Domains
  -------------------- ----------- ---------
  Train                  1,043,526   817,407
  Validation               148,086   116,772
  Test                     150,409   116,773
  Unseen-domain test       138,869   116,773

### Purpose

A random URL-level split can place URLs from the same domain into both
training and testing data.

For example:

``` text
Training:
example.com/login

Testing:
example.com/account
```

Such a split can make the model appear more accurate than it really is
because it has already seen the domain during training.

The domain-aware split instead evaluates whether the model can
generalize to domains that were not available during training.

------------------------------------------------------------------------

## 9. Unseen-Domain Evaluation

The `unseen_domain_test.csv` dataset is reserved specifically for
evaluating generalization to previously unseen domains.

This is an important evaluation set for AI WatchDog because the final
system should not only memorize known phishing domains; it should
identify suspicious characteristics in URLs from domains it has not
encountered before.

The unseen-domain test should therefore remain isolated until final
evaluation.

------------------------------------------------------------------------

## 10. Temporal Evaluation Limitation

A temporal test set was **not generated** in Phase 1.5.

Reason:

``` text
The current 20-column master schema does not contain
a reliable collection/submission timestamp.
```

A temporal test set should not be created by inventing dates or using
unreliable file modification times.

If reliable timestamps become available from the original datasets, a
future temporal evaluation split can be added.

------------------------------------------------------------------------

## 11. Feature Leakage Considerations

The following fields should be treated carefully:

### `label`

This is the target variable and must never be included as an input
feature.

### `source`

`source` should be excluded from model training because the model could
learn characteristics of the datasets rather than characteristics of
phishing URLs.

### `domain`

`domain` should primarily be used for grouping and leakage-controlled
splitting. Feeding the raw domain string directly into a baseline
classifier can cause memorization of domains rather than learning
general phishing characteristics.

### `url`

The raw URL can be useful for later advanced models, but the initial
classical ML models should primarily use engineered numerical/Boolean
URL features.

------------------------------------------------------------------------

## 12. Current Phase 1 Deliverables

The following outputs have been generated:

``` text
data/
├── phishing_master.csv
│
├── analysis/
│   ├── data_quality.csv
│   ├── domain_label_conflicts.csv
│   ├── label_distribution.csv
│   ├── numeric_feature_statistics.csv
│   ├── security_features.csv
│   ├── source_distribution.csv
│   ├── split_domain_overlap.csv
│   ├── split_label_distribution.csv
│   ├── top_tlds.csv
│   └── phase1_analysis_report.txt
│
└── splits/
    ├── train.csv
    ├── validation.csv
    ├── test.csv
    └── unseen_domain_test.csv
```

------------------------------------------------------------------------

## 13. Phase 1 Findings

### Strengths

-   Large dataset with **1.48 million URLs**.
-   Multiple independent URL sources.
-   Binary labels are clearly defined.
-   No duplicate URLs remain.
-   20-column schema is consistent.
-   URL lexical features have already been extracted.
-   Domain-aware splitting reduces a major source of evaluation leakage.
-   A dedicated unseen-domain test set is available.
-   Dataset provenance is preserved.

### Issues requiring attention

1.  **474 conflicting-label domains** require investigation.
2.  **12 URL-level label conflicts** should be documented and
    resolved/handled before final training.
3.  The dataset does not currently contain reliable timestamps,
    preventing temporal evaluation.
4.  Class imbalance should be handled during training/evaluation rather
    than by modifying the master dataset.
5.  `source` must be excluded from the model feature matrix.
6.  Domain leakage must continue to be controlled during all
    experiments.

------------------------------------------------------------------------

## 14. Phase 1 Conclusion

The AI WatchDog master dataset has successfully completed the primary
Phase 1 data-collection, cleaning, labeling, feature-extraction, and
leakage-aware splitting requirements.

The final dataset contains:

> **1,480,890 unique labeled URLs with 20 columns and a 90.81% benign /
> 9.19% phishing class distribution.**

The dataset is now suitable for **Phase 2: Feature Analysis and Feature
Engineering**.

Before model training, the next stage should:

1.  Analyze the statistical distributions of all candidate features.
2.  Compare feature behavior between benign and phishing URLs.
3.  Measure feature correlations and redundancy.
4.  Check for target/data leakage.
5.  Investigate the 474 conflicting domains and 12 URL-level conflicts.
6.  Evaluate feature importance using the training data only.
7.  Select the final feature set.
8.  Prepare the feature matrices for baseline ML models.

**Phase 1 status: COMPLETE ✅**

**Next phase: Phase 2 --- Feature Analysis & Engineering**
