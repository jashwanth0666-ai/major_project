package com.aiwatchdog.backend.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

import java.util.ArrayList;
import java.util.List;

/** Bounded, page-local structural counters. Never contains page text or form values. */
public record PageSignals(
        @Min(0) @Max(50) int passwordFormCount,
        @Min(0) @Max(50) int crossOriginPasswordFormCount,
        @Min(0) @Max(50) int insecurePasswordFormCount,
        @Min(0) @Max(50) int hiddenFrameCount,
        @Min(0) @Max(50) int crossOriginFrameCount) {

    public List<String> securityReasons() {
        List<String> reasons = new ArrayList<>();
        if (crossOriginPasswordFormCount > 0) {
            reasons.add("A password form submits to a different site origin.");
        }
        if (insecurePasswordFormCount > 0) {
            reasons.add("A password form submits without HTTPS protection.");
        }
        if (hiddenFrameCount >= 3) {
            reasons.add("Several hidden frames are present; this is a weak indicator and can occur on legitimate sites.");
        }
        return List.copyOf(reasons);
    }

    public boolean hasCredentialRisk() {
        return crossOriginPasswordFormCount > 0 || insecurePasswordFormCount > 0;
    }
}
