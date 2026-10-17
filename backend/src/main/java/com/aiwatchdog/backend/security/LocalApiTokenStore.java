package com.aiwatchdog.backend.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;

/** Reads per-client local API credentials from the current user's protected credential file. */
@Component
public final class LocalApiTokenStore {
    private final Path tokenFile;
    private final ObjectMapper mapper = new ObjectMapper();

    public LocalApiTokenStore(@Value("${ai-watchdog.security.token-file:}") String configuredPath) {
        if (configuredPath != null && !configuredPath.isBlank()) {
            tokenFile = Path.of(configuredPath).toAbsolutePath().normalize();
        } else {
            String appData = System.getenv("APPDATA");
            tokenFile = appData != null && !appData.isBlank()
                    ? Path.of(appData, "AIWatchDog", "auth", "api-tokens.json")
                    : Path.of(System.getProperty("user.home"), ".aiwatchdog", "api-tokens.json");
        }
    }

    public String token(String client) {
        String environmentName = "springToMl".equals(client)
                ? "AI_WATCHDOG_SPRING_TO_ML_TOKEN"
                : "AI_WATCHDOG_" + client.toUpperCase() + "_TOKEN";
        String environment = System.getenv(environmentName);
        if (environment != null && environment.trim().matches("(?i)[a-f0-9]{64,}")) return environment.trim();
        try {
            if (!Files.isRegularFile(tokenFile)) return null;
            JsonNode value = mapper.readTree(tokenFile.toFile()).path(client);
            String token = value.isTextual() ? value.asText().trim() : "";
            return token.matches("(?i)[a-f0-9]{64,}") ? token : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    public Path tokenFile() { return tokenFile; }
}
