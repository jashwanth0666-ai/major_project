package com.aiwatchdog.backend.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Bounded browser evidence: structural counters and redirect hostnames, never page text or form values. */
public record PageSignals(
        @Min(0) @Max(50) int passwordFormCount,
        @Min(0) @Max(50) int crossOriginPasswordFormCount,
        @Min(0) @Max(50) int insecurePasswordFormCount,
        @Min(0) @Max(50) int hiddenFrameCount,
        @Min(0) @Max(50) int crossOriginFrameCount,
        @Size(max = 6) List<@NotBlank @Size(max = 253) @Pattern(regexp = "[A-Za-z0-9.-]+") String> redirectHosts) {

    public PageSignals {
        redirectHosts = redirectHosts == null ? List.of() : List.copyOf(redirectHosts);
    }

    public PageSignals(int passwordFormCount, int crossOriginPasswordFormCount,
                       int insecurePasswordFormCount, int hiddenFrameCount, int crossOriginFrameCount) {
        this(passwordFormCount, crossOriginPasswordFormCount, insecurePasswordFormCount, hiddenFrameCount,
                crossOriginFrameCount, List.of());
    }

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
        long distinctRedirectHosts = redirectHosts.stream().map(host -> host.toLowerCase(Locale.ROOT)).distinct().count();
        if (distinctRedirectHosts > 1) {
            reasons.add("The browser observed redirects across " + distinctRedirectHosts
                    + " hostnames; review the hostname sequence in the assessment evidence.");
        }
        return List.copyOf(reasons);
    }

    public boolean hasCredentialRisk() {
        return crossOriginPasswordFormCount > 0 || insecurePasswordFormCount > 0;
    }
}
