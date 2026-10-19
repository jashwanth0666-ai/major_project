package com.aiwatchdog.backend.policy;

import org.springframework.stereotype.Service;

@Service
public class PolicyEngineImpl implements PolicyEngine {

    @Override
    public Decision evaluate(PolicyRequest request) {
        validateRequest(request);
        Decision modelDecision = evaluateRiskLevel(RiskLevel.parse(request.riskLevel()));
        String noUrlIndicators = "No major URL-level warning indicators detected";
        boolean modelOnlyHighRisk = RiskLevel.parse(request.riskLevel()) == RiskLevel.HIGH_RISK
                && "PHISHING".equalsIgnoreCase(request.prediction().trim())
                && (request.reasons().isEmpty()
                || request.reasons().stream().anyMatch(reason -> noUrlIndicators.equalsIgnoreCase(reason)));
        // The model can be overconfident on out-of-distribution URLs. If its own
        // independent URL checks found no corroborating warning signal, hold for
        // review instead of blocking solely on the model score.
        if (!modelOnlyHighRisk) return modelDecision;
        boolean externalPassword = request.reasons().stream()
                .anyMatch(reason -> "A password form submits to a different site origin.".equals(reason));
        boolean insecurePassword = request.reasons().stream()
                .anyMatch(reason -> "A password form submits without HTTPS protection.".equals(reason));
        if (externalPassword && insecurePassword) return Decision.BLOCK;
        if (externalPassword || insecurePassword) return Decision.WARN;
        return Decision.REVIEW;
    }

    @Override
    public Decision evaluateRiskLevel(RiskLevel riskLevel) {
        if (riskLevel == null) throw new IllegalArgumentException("risk_level is required.");
        return switch (riskLevel) {
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
