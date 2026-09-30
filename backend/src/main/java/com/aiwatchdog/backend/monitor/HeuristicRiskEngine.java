package com.aiwatchdog.backend.monitor;

import com.aiwatchdog.backend.policy.RiskLevel;
import org.springframework.stereotype.Component;
import java.util.List;

@Component
public class HeuristicRiskEngine {
    public RiskAssessment assess(AnalysisSignals signals) {
        int score = Math.max(0, Math.min(100, signals.score()));
        RiskLevel level = score <= 25 ? RiskLevel.SAFE
                : score <= 50 ? RiskLevel.LOW_RISK
                : score <= 75 ? RiskLevel.SUSPICIOUS
                : RiskLevel.HIGH_RISK;
        List<String> reasons = signals.reasons().isEmpty()
                ? List.of("No configured name-based risk rule matched; this is not a malware verdict")
                : signals.reasons();
        return new RiskAssessment(score, level, reasons);
    }
}
