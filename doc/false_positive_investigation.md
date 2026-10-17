# AI WatchDog false positive investigation

## Finding

The available source does not support an implementation mismatch in the URL feature pipeline or a response/UI remapping bug as the cause of the reported false positives. The false positive demonstrated in the checked-in Phase 5 report is produced by the model itself: `https://www.youtube.com/` has calibrated phishing probability `0.461707`, model label `PHISHING` at threshold `0.15`, risk score `46`, risk level `LOW_RISK`, and policy decision `REVIEW`. It is therefore a model false positive, but it is not `HIGH_RISK` and does not produce policy `BLOCK`.

The probability and stages for the supplied short URL `https://youtu.be/Wo3__JUisj8?si=qw5ReP8d-HBiXPVJ` remain unknown. Inference was intentionally not run. No source evidence justifies altering the model, its calibrated probabilities, its `0.15` threshold, the risk bands, or policy behavior. No speculative source correction was made.

## Source trace

| Stage | Source and behavior |
|---|---|
| Original URL | Spring `AnalysisService.assess(url)` validates and forwards the submitted URL unchanged to `MlServiceClient.predict(url)`. |
| Normalized URL | FastAPI `predict` trims surrounding whitespace; `scripts/phase5_inference.py::extract_features` calls `normalize_url`. It inserts `http://` when no scheme exists, removes spaces, lowercases scheme/host, strips trailing path slash and default port spellings, and preserves query text. The returned `url` field is the submitted string, not the feature-normalized string. |
| Features | `extract_features` parses host/path/query separately and creates the configured 25 ordered features; `build_model_input` casts them to `float32`. Phase 5 base features reproduce `scripts/create_master.py::extract_features`; engineered features reproduce `scripts/phase4_calibration_threshold.py::engineer`. The lists and order match `data/phase4/risk_engine_config.json`. |
| Raw/calibrated output | `WatchDogDetector.predict` calls `self.model.predict_proba(X)[0, 1]` and treats column 1 as phishing, consistent with Phase 4 training labels (`benign=0`, `phishing=1`) and its `[:, 1]` evaluation. The checked-in artifact is integrity-checked before loading by `api/server.py` and is SHA-256 pinned in `api/config.py`. |
| Model label | `WatchDogDetector.predict`: `PHISHING` when probability `>= 0.15`, otherwise `BENIGN`. The threshold is unchanged. |
| Risk score/level | `risk_score = round(probability * 100)` clipped to 0–100; `risk_level` uses separate score bands. A `HIGH_RISK` score requires 76 or higher (probability around 0.755 or higher, subject to rounding). |
| Policy | Spring `AnalysisService.assess` passes the ML fields to `PolicyEngine`; `PolicyEngineImpl` maps `SAFE→ALLOW`, `LOW_RISK→REVIEW`, `SUSPICIOUS→WARN`, `HIGH_RISK→BLOCK`. Policy does not recalculate model probability. |
| API response | `AnalyzeResponse` carries probability, score, risk level, prediction, decision, threshold, and reasons as distinct fields. `MlServiceClient` rejects malformed or out-of-range responses. API errors are returned as errors, not safe verdicts. |
| Extension | Search-result previews call `/api/v1/analyze/preview`; actual navigations call `/api/v1/analyze`. Both normalize the same response fields. Only actual analysis logs an event (`AnalysisService.analyze`); preview does not. Extension warning and redirect rule require both `decision=BLOCK` and `risk_level=HIGH_RISK`; unavailable assessments remain unknown/unavailable. |

## Why the symptom cannot be corrected from current evidence

The code and existing parity test source show matching training/inference feature definitions. The available model report demonstrates that an unrelated, ordinary video site can score above the model classification threshold without entering the high-risk band. This supports a model generalization/false-positive issue for at least that reported root URL. It does not establish the supplied short URL's output, a population-wide false-positive cause, or any wrong feature value for that URL.

The Phase 5 feature parity test source is present but was not executed, as required. The model artifact was not loaded for an ad hoc prediction. The artifact's runtime class metadata and the exact supplied URL's feature/probability trace are therefore unverified in this investigation. No runtime behavior is claimed as verified.

## Remaining evidence needed

- Obtain a permitted inference trace for the exact short URL: normalized string, 25 ordered feature values, model output, calibrated probability, score, level, and prediction.
- Compare that trace with an independently recorded training-pipeline feature row for the same normalized URL.
- Evaluate an approved, labeled benign/phishing test set with URL-level and domain-level false-positive analysis; identify patterns without selecting a threshold from one sample.
- If a future source mismatch is established, document it and make only the corresponding minimal correction. Any model recalibration or retraining requires a separate evidence-backed model change.

## Change summary

No application source, API contract, database schema, model artifact, threshold, risk configuration, policy implementation, or extension behavior was changed. `testing.md` now records the requested unexecuted regression plan.
