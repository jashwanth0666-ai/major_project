package com.aiwatchdog.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Protects every Spring route except the read-only liveness/health endpoint. */
@Component
@ConditionalOnProperty(name = "ai-watchdog.security.enabled", havingValue = "true", matchIfMissing = true)
public final class LocalApiAuthenticationFilter extends OncePerRequestFilter {
    private static final String TOKEN_HEADER = "Authorization";
    private final LocalApiTokenStore tokens;

    public LocalApiAuthenticationFilter(LocalApiTokenStore tokens) { this.tokens = tokens; }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return "GET".equals(request.getMethod()) && "/api/v1/health".equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (!credentialsConfigured()) {
            reject(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "LOCAL_AUTH_NOT_CONFIGURED",
                    "Local API credentials are not configured. Run setup-local-auth.ps1.");
            return;
        }
        String supplied = request.getHeader(TOKEN_HEADER);
        if (supplied == null || !supplied.startsWith("Bearer ")) {
            reject(response, HttpServletResponse.SC_UNAUTHORIZED, "AUTHENTICATION_REQUIRED",
                    "A valid local API credential is required.");
            return;
        }
        String token = supplied.substring("Bearer ".length());
        String role = matchingClient(token);
        if (role == null) {
            reject(response, HttpServletResponse.SC_UNAUTHORIZED, "INVALID_CREDENTIAL",
                    "The local API credential is invalid.");
            return;
        }
        if ("extension".equals(role)
                && !("GET".equals(request.getMethod())
                && "/api/v1/domain-whitelist".equals(request.getRequestURI())
                || "POST".equals(request.getMethod())
                && ("/api/v1/threat-assessments/url".equals(request.getRequestURI())
                || "/api/v1/threat-assessments/url/preview".equals(request.getRequestURI())
                || "/api/v1/threat-assessments/feedback".equals(request.getRequestURI())))) {
            reject(response, HttpServletResponse.SC_FORBIDDEN, "INSUFFICIENT_SCOPE",
                    "The browser extension credential can assess URLs, read configured domain exceptions, and submit assessment feedback only.");
            return;
        }
        chain.doFilter(request, response);
    }

    private String matchingClient(String supplied) {
        for (String role : new String[]{"desktop", "extension"}) {
            String expected = tokens.token(role);
            if (expected != null && MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                    supplied.getBytes(StandardCharsets.UTF_8))) return role;
        }
        return null;
    }

    private boolean credentialsConfigured() {
        return tokens.token("desktop") != null || tokens.token("extension") != null;
    }

    private void reject(HttpServletResponse response, int status, String code, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + code + "\",\"message\":\"" + message + "\"}");
    }
}
