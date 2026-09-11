package com.aiwatchdog.backend.policy;

import java.util.Locale;

public enum RiskLevel {
    SAFE,
    LOW_RISK,
    SUSPICIOUS,
    HIGH_RISK;

    public static RiskLevel parse(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("risk_level is required.");
        }

        String normalized = value.trim()
                .toUpperCase(Locale.ROOT)
                .replace(' ', '_');

        try {
            return valueOf(normalized);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unsupported risk_level: " + value);
        }
    }
}