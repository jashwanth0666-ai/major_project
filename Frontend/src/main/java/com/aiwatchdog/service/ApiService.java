package com.aiwatchdog.service;

import com.aiwatchdog.model.AnalyzeRequest;
import com.aiwatchdog.model.AnalyzeResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
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
            return mapper.readValue(response.body(), AnalyzeResponse.class);
        } else {
            throw new RuntimeException("API error: " + response.statusCode() + " - " + response.body());
        }
    }
}
