package com.aiwatchdog.backend.policy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PolicyEngineImplTest {

    private final PolicyEngine engine = new PolicyEngineImpl();

    @Test
    void mapsRiskLevelsToDecisions() {
        assertEquals(Decision.ALLOW, engine.evaluate(request("SAFE", "BENIGN")));
        assertEquals(Decision.REVIEW, engine.evaluate(request("LOW_RISK", "BENIGN")));
        assertEquals(Decision.WARN, engine.evaluate(request("SUSPICIOUS", "PHISHING")));
        assertEquals(Decision.BLOCK, engine.evaluate(request("HIGH RISK", "PHISHING")));
    }

    @Test
    void rejectsInvalidSecurityValues() {
        assertRejects(new PolicyRequest("url", -0.1, 10, "SAFE", "BENIGN"));
        assertRejects(new PolicyRequest("url", 1.5, 10, "SAFE", "BENIGN"));
        assertRejects(new PolicyRequest("url", Double.NaN, 10, "SAFE", "BENIGN"));
        assertRejects(new PolicyRequest("url", 0.1, -1, "SAFE", "BENIGN"));
        assertRejects(new PolicyRequest("url", 0.1, 101, "SAFE", "BENIGN"));
        assertRejects(new PolicyRequest("url", 0.1, 10, "UNKNOWN", "BENIGN"));
        assertRejects(new PolicyRequest("url", 0.1, 10, null, "BENIGN"));
        assertRejects(new PolicyRequest("url", 0.1, 10, "SAFE", "UNKNOWN"));
    }

    @Test
    void invalidSecurityValuesNeverReturnAllow() {
        assertThrows(IllegalArgumentException.class,
                () -> engine.evaluate(new PolicyRequest("url", 2.0, 10, "SAFE", "BENIGN")));
    }

    private static PolicyRequest request(String riskLevel, String prediction) {
        return new PolicyRequest("https://example.com", 0.1, 10, riskLevel, prediction);
    }

    private void assertRejects(PolicyRequest request) {
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(request));
    }
}