package com.aiwatchdog.backend.policy;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PolicyEngineImplTest {

    private final PolicyEngine engine = new PolicyEngineImpl();

    private PolicyRequest createRequest(double prob, int score, String level, String pred) {
        return new PolicyRequest("https://example.com", prob, score, level, pred);
    }

    @Test
    void testPolicyMapping() {
        assertEquals(Decision.ALLOW, engine.evaluate(createRequest(0.1, 10, "SAFE", "BENIGN")));
        assertEquals(Decision.REVIEW, engine.evaluate(createRequest(0.4, 40, "LOW_RISK", "PHISHING")));
        assertEquals(Decision.WARN, engine.evaluate(createRequest(0.6, 60, "SUSPICIOUS", "PHISHING")));
        assertEquals(Decision.BLOCK, engine.evaluate(createRequest(0.9, 90, "HIGH_RISK", "PHISHING")));
    }

    @Test
    void testRiskBoundaries() {
        // Just testing boundaries of RiskLevel validity in policy engine (not risk_score to RiskLevel conversion,
        // because risk_score to RiskLevel is done in Risk Engine/FastAPI, but we test validation here)
        assertEquals(Decision.ALLOW, engine.evaluate(createRequest(0.0, 0, "SAFE", "BENIGN")));
        assertEquals(Decision.ALLOW, engine.evaluate(createRequest(0.25, 25, "SAFE", "BENIGN")));
        assertEquals(Decision.REVIEW, engine.evaluate(createRequest(0.26, 26, "LOW_RISK", "BENIGN")));
        assertEquals(Decision.REVIEW, engine.evaluate(createRequest(0.50, 50, "LOW_RISK", "BENIGN")));
        assertEquals(Decision.WARN, engine.evaluate(createRequest(0.51, 51, "SUSPICIOUS", "BENIGN")));
        assertEquals(Decision.WARN, engine.evaluate(createRequest(0.75, 75, "SUSPICIOUS", "BENIGN")));
        assertEquals(Decision.BLOCK, engine.evaluate(createRequest(0.76, 76, "HIGH_RISK", "PHISHING")));
        assertEquals(Decision.BLOCK, engine.evaluate(createRequest(1.0, 100, "HIGH_RISK", "PHISHING")));
    }

    @Test
    void testInvalidRiskScores() {
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(0.1, -1, "SAFE", "BENIGN")));
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(0.9, 101, "HIGH_RISK", "PHISHING")));
    }

    @Test
    void testInvalidProbability() {
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(-0.1, 10, "SAFE", "BENIGN")));
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(1.1, 90, "HIGH_RISK", "PHISHING")));
    }

    @Test
    void testInvalidRiskLevels() {
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(0.1, 10, null, "BENIGN")));
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(0.1, 10, "UNKNOWN", "BENIGN")));
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(0.1, 10, "", "BENIGN")));
    }

    @Test
    void testInvalidPrediction() {
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(0.1, 10, "SAFE", null)));
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(0.1, 10, "SAFE", "UNKNOWN")));
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(createRequest(0.1, 10, "SAFE", "")));
    }

    @Test
    void testDeterminism() {
        PolicyRequest req = createRequest(0.1, 10, "SAFE", "BENIGN");
        Decision d1 = engine.evaluate(req);
        Decision d2 = engine.evaluate(req);
        Decision d3 = engine.evaluate(req);
        assertEquals(Decision.ALLOW, d1);
        assertEquals(d1, d2);
        assertEquals(d2, d3);
    }
}
