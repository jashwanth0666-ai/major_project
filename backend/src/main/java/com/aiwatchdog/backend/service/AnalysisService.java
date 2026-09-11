package com.aiwatchdog.backend.service;

import com.aiwatchdog.backend.dto.AnalyzeResponse;
import com.aiwatchdog.backend.dto.MlPredictionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;

@Service
public class AnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(AnalysisService.class);

    private final MlServiceClient mlServiceClient;

    public AnalysisService(MlServiceClient mlServiceClient) {
        this.mlServiceClient = mlServiceClient;
    }

    public AnalyzeResponse analyze(String url) {

        validateUrl(url);
        logger.info("Analysis request received");

        MlPredictionResponse mlResult = mlServiceClient.predict(url);

        logger.info("ML analysis completed");

        return new AnalyzeResponse(
                mlResult.url(),
                mlResult.phishing_probability(),
                mlResult.risk_score(),
                mlResult.risk_level(),
                mlResult.prediction(),
                mlResult.decision(),
                mlResult.threshold(),
                mlResult.reasons());
    }

    private void validateUrl(String url) {

        if (url == null || url.isBlank()) {
            throw new InvalidRequestException("URL must not be empty.");
        }

        try {
            URI parsedUrl = new URI(url);

            if (!("http".equalsIgnoreCase(parsedUrl.getScheme())
                    || "https".equalsIgnoreCase(parsedUrl.getScheme()))
                    || parsedUrl.getHost() == null
                    || parsedUrl.getHost().isBlank()) {
                throw new InvalidRequestException("URL must be a valid HTTP or HTTPS URL.");
            }
        } catch (URISyntaxException ex) {
            throw new InvalidRequestException("URL must be a valid HTTP or HTTPS URL.");
        }
    }
}