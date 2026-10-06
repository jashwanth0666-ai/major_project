package com.aiwatchdog.backend.policy;

public interface PolicyEngine {
    Decision evaluate(PolicyRequest request);
    Decision evaluateRiskLevel(RiskLevel riskLevel);
}
