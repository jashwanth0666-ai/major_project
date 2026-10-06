package com.aiwatchdog.backend.service;

import com.aiwatchdog.backend.dto.AnalyzeResponse;
import com.aiwatchdog.backend.dto.MlPredictionResponse;
import com.aiwatchdog.backend.logging.SecurityEvent;
import com.aiwatchdog.backend.logging.SecurityEventLogger;
import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.PolicyEngine;
import com.aiwatchdog.backend.policy.PolicyRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.regex.Pattern;

@Service
public class AnalysisService {

    private static final Pattern SENSITIVE_PATH = Pattern.compile(
            "(?i)(token|session|password|secret|credential|access[_-]?key|auth[_-]?code)");
    private static final Pattern OPAQUE_PATH_SEGMENT = Pattern.compile("[A-Za-z0-9_-]{32,}");

    private static final Logger logger =
            LoggerFactory.getLogger(AnalysisService.class);

    private final MlServiceClient mlServiceClient;
    private final PolicyEngine policyEngine;
    private final SecurityEventLogger securityEventLogger;

    public AnalysisService(
            MlServiceClient mlServiceClient,
            PolicyEngine policyEngine,
            SecurityEventLogger securityEventLogger) {

        this.mlServiceClient = mlServiceClient;
        this.policyEngine = policyEngine;
        this.securityEventLogger = securityEventLogger;
    }

    public AnalyzeResponse analyze(String url) {

        validateUrl(url);
        logger.info("Analysis request received");

        MlPredictionResponse mlResult =
                mlServiceClient.predict(url);

        logger.info("ML analysis completed");

        PolicyRequest policyRequest = new PolicyRequest(
                mlResult.url(),
                mlResult.phishing_probability(),
                mlResult.risk_score(),
                mlResult.risk_level(),
                mlResult.prediction());

        Decision finalDecision =
                policyEngine.evaluate(policyRequest);

        SecurityEvent event = new SecurityEvent(
                null,
                null,
                auditUrl(url),
                mlResult.phishing_probability(),
                mlResult.risk_score(),
                mlResult.risk_level(),
                mlResult.prediction(),
                finalDecision.name());

        securityEventLogger.log(event);

        return new AnalyzeResponse(
                mlResult.url(),
                mlResult.phishing_probability(),
                mlResult.risk_score(),
                mlResult.risk_level(),
                mlResult.prediction(),
                finalDecision.name(),
                mlResult.threshold(),
                mlResult.reasons());
    }

    private String auditUrl(String rawUrl) {
        try {
            URI parsed = new URI(rawUrl);
            String path = parsed.getPath() == null ? "" : parsed.getPath();
            boolean sensitive = Arrays.stream(path.split("/"))
                    .anyMatch(segment -> SENSITIVE_PATH.matcher(segment).find()
                            || OPAQUE_PATH_SEGMENT.matcher(segment).matches());
            if (sensitive) path = "/";
            return new URI(parsed.getScheme(), null, parsed.getHost(), parsed.getPort(),
                    path, null, null).toASCIIString();
        } catch (URISyntaxException | IllegalArgumentException exception) {
            // Validation has already accepted the URL; fail closed for logging if normalization fails.
            return "[redacted URL]";
        }
    }

    private void validateUrl(String url) {

        if (url == null || url.isBlank()) {
            throw new InvalidRequestException(
                    "URL must not be empty.");
        }

        try {
            URI parsedUrl = new URI(url);

            if (!("http".equalsIgnoreCase(parsedUrl.getScheme())
                    || "https".equalsIgnoreCase(parsedUrl.getScheme()))
                    || parsedUrl.getHost() == null
                    || parsedUrl.getHost().isBlank()) {

                throw new InvalidRequestException(
                        "URL must be a valid HTTP or HTTPS URL.");
            }

        } catch (URISyntaxException ex) {

            throw new InvalidRequestException(
                    "URL must be a valid HTTP or HTTPS URL.");
        }
    }
}
