package com.aiwatchdog.backend.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "ai-watchdog.ml")
public record MlServiceConfig(
                String baseUrl,
                int connectTimeoutMs,
                int readTimeoutMs) {
}