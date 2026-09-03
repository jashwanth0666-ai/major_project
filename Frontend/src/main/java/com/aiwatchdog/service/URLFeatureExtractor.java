package com.aiwatchdog.service;

import java.util.List;

public class URLFeatureExtractor {
    public List<String> extract(String url) {
        String value = url == null ? "" : url.trim();
        String lower = value.toLowerCase();
        return List.of(
                "URL length: " + value.length(),
                "HTTPS enabled: " + lower.startsWith("https://"),
                "IP address used: " + lower.matches("https?://\\d{1,3}(\\.\\d{1,3}){3}.*"),
                "Subdomains: " + Math.max(0, lower.split("\\.").length - 2),
                "Suspicious keywords: "
                        + lower.matches(".*(login|verify|account|security|update|bank|password|confirm).*"));
    }
}
