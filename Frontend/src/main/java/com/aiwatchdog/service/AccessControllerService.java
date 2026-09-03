package com.aiwatchdog.service;

import com.aiwatchdog.model.AccessDecision;
import com.aiwatchdog.model.ThreatLevel;

public class AccessControllerService {
    public AccessDecision decide(ThreatLevel level) {
        return switch (level) {
            case SAFE -> AccessDecision.ALLOW;
            case SUSPICIOUS -> AccessDecision.WARN;
            case HIGH_RISK -> AccessDecision.RESTRICT;
            case PHISHING -> AccessDecision.BLOCK;
        };
    }
}
