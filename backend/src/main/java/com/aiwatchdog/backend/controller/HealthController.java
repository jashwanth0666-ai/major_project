package com.aiwatchdog.backend.controller;

import com.aiwatchdog.backend.service.MlServiceClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class HealthController {

    private final MlServiceClient mlServiceClient;

    public HealthController(MlServiceClient mlServiceClient) {
        this.mlServiceClient = mlServiceClient;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {

        boolean mlHealthy = mlServiceClient.isHealthy();

        Map<String, Object> response = Map.of(
                "status", mlHealthy ? "OK" : "DEGRADED",
                "spring_boot", "UP",
                "ml_service", mlHealthy ? "UP" : "DOWN");

        return ResponseEntity
                .status(
                        mlHealthy
                                ? HttpStatus.OK
                                : HttpStatus.SERVICE_UNAVAILABLE)
                .body(response);
    }
}