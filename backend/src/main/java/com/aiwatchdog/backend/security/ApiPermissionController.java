package com.aiwatchdog.backend.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** Exposes human-readable scopes, never credentials. Access is desktop-client only. */
@RestController
@RequestMapping("/api/v1/security")
public class ApiPermissionController {
    private final LocalApiTokenStore tokens;

    public ApiPermissionController(LocalApiTokenStore tokens) { this.tokens = tokens; }

    @GetMapping("/permissions")
    public ApiPermissionCapabilities permissions() {
        return new ApiPermissionCapabilities(
                new ApiClientPermission(tokens.token("desktop") != null,
                        List.of("Use desktop analysis and activity APIs", "Manage File Shield scan and quarantine settings",
                                "Manage local Windows telemetry collection settings", "Review and export stored security events")),
                new ApiClientPermission(tokens.token("extension") != null,
                        List.of("Assess the active URL", "Read configured domain exceptions", "Submit assessment feedback")),
                "Spring Boot enforces separate desktop and browser-extension credentials on every API request.",
                "Windows event-log access and process/script audit policies are controlled by Windows and may require an administrator.");
    }
}
