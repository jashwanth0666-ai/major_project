package com.aiwatchdog.service;

import com.aiwatchdog.model.AnalyzeRequest;
import com.aiwatchdog.model.AnalyzeResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class ApiService {

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private static final String BASE_URL = "http://localhost:8080/api/v1";

    public ApiService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.mapper = new ObjectMapper();
    }

    public AnalyzeResponse analyzeUrl(String url) throws Exception {
        AnalyzeRequest requestObj = new AnalyzeRequest(url);
        String requestBody = mapper.writeValueAsString(requestObj);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/analyze"))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(15))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            if (response.body() == null || response.body().isBlank()) {
                throw new IOException("Backend returned an empty analysis response.");
            }

            AnalyzeResponse result = mapper.readValue(response.body(), AnalyzeResponse.class);
            if (result == null) {
                throw new IOException("Backend returned an empty analysis response.");
            }
            return result;
        } else {
            throw new IOException("Backend analysis failed with HTTP " + response.statusCode() + ".");
        }
    }

    public boolean isBackendHealthy() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/health"))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300
                || response.body() == null || response.body().isBlank()) {
            return false;
        }

        var health = mapper.readTree(response.body());
        return "OK".equalsIgnoreCase(health.path("status").asText())
                && "UP".equalsIgnoreCase(health.path("spring_boot").asText())
                && "UP".equalsIgnoreCase(health.path("ml_service").asText());
    }
}
