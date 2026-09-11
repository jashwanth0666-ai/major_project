package com.aiwatchdog.backend.policy;

import org.springframework.stereotype.Service;

@Service
public class PolicyEngineImpl implements PolicyEngine {

    @Override
    public Decision evaluate(PolicyRequest request) {
        validateRequest(request);

        return switch (RiskLevel.parse(request.riskLevel())) {
            case SAFE -> Decision.ALLOW;
            case LOW_RISK -> Decision.REVIEW;
            case SUSPICIOUS -> Decision.WARN;
            case HIGH_RISK -> Decision.BLOCK;
        };
    }

    private void validateRequest(PolicyRequest request) {
        if (request == null
                || request.url() == null || request.url().isBlank()
                || request.phishingProbability() == null
                || request.riskScore() == null
                || request.riskLevel() == null || request.riskLevel().isBlank()
                || request.prediction() == null || request.prediction().isBlank()) {
            throw new IllegalArgumentException("All policy request values are required.");
        }

        if (!Double.isFinite(request.phishingProbability())
                || request.phishingProbability() < 0.0
                || request.phishingProbability() > 1.0) {
            throw new IllegalArgumentException("phishing_probability must be between 0.0 and 1.0.");
        }
        if (request.riskScore() < 0 || request.riskScore() > 100) {
            throw new IllegalArgumentException("risk_score must be between 0 and 100.");
        }

        RiskLevel.parse(request.riskLevel());
        if (!"BENIGN".equalsIgnoreCase(request.prediction().trim())
                && !"PHISHING".equalsIgnoreCase(request.prediction().trim())) {
            throw new IllegalArgumentException("Unsupported prediction: " + request.prediction());
        }
    }
}