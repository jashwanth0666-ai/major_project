package com.aiwatchdog.service;

import com.aiwatchdog.model.AnalysisResult;
import com.aiwatchdog.model.ThreatLevel;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class DemoPhishingDetectionEngine implements PhishingDetectionEngine {
    @Override
    public AnalysisResult analyze(String rawUrl) {
        String url = rawUrl == null ? "" : rawUrl.trim();
        if (!url.matches("(?i)^https?://.*"))
            url = "https://" + url;
        String lower = url.toLowerCase();
        int score = 0;
        List<String> reasons = new ArrayList<>();
        if (!lower.startsWith("https://")) {
            score += 15;
            reasons.add("HTTPS is not enabled");
        }
        boolean ip = lower.matches("https?://\\d{1,3}(\\.\\d{1,3}){3}.*");
        if (ip) {
            score += 30;
            reasons.add("IP address used instead of a domain");
        }
        if (lower.matches(".*(login|verify|account|security|update|bank|password|confirm).*")) {
            score += 15;
            reasons.add("Sensitive keyword detected");
        }
        if (url.length() > 75) {
            score += 10;
            reasons.add("Abnormally long URL");
        }
        try {
            String host = URI.create(url).getHost();
            int dots = host == null ? 0 : host.chars().filter(c -> c == '.').sum();
            if (dots > 2) {
                score += 10;
                reasons.add("Multiple subdomains detected");
            }
        } catch (IllegalArgumentException ignored) {
            score += 15;
            reasons.add("Malformed domain structure");
        }
        if (lower.contains("@") || lower.chars().filter(c -> c == '=' || c == '&').count() > 3) {
            score += 10;
            reasons.add("Suspicious URL parameters");
        }
        if (lower.matches(".*(bit\\.ly|tinyurl|t\\.co)/.*")) {
            score += 10;
            reasons.add("URL shortening service detected");
        }
        if (lower.contains("example.com") || lower.contains("example.net") || ip) {
            score += 15;
            reasons.add("Suspicious domain pattern");
        }
        score = Math.min(100, score);
        ThreatLevel level = score >= 80 ? ThreatLevel.PHISHING
                : score >= 60 ? ThreatLevel.HIGH_RISK : score >= 30 ? ThreatLevel.SUSPICIOUS : ThreatLevel.SAFE;
        if (reasons.isEmpty())
            reasons.add("No significant phishing indicators were detected");
        String decision = level == ThreatLevel.SAFE ? "ACCESS ALLOWED"
                : level == ThreatLevel.SUSPICIOUS ? "ACCESS REQUIRES ATTENTION"
                        : level == ThreatLevel.HIGH_RISK ? "ACCESS RESTRICTED" : "ACCESS BLOCKED";
        List<String> features = List.of("URL length: " + url.length(), "HTTPS enabled: " + lower.startsWith("https://"),
                "IP address: " + ip,
                "Suspicious keywords: "
                        + (lower.matches(".*(login|verify|account|security|update|bank|password|confirm).*")),
                "Special parameters: " + (lower.contains("@") || lower.contains("=")));
        return new AnalysisResult(url, level, score, Math.min(99, 82 + score / 6), reasons, features, decision);
    }
}
