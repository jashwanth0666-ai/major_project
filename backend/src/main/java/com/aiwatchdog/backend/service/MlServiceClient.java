package com.aiwatchdog.backend.service;

import com.aiwatchdog.backend.config.MlServiceConfig;
import com.aiwatchdog.backend.dto.MlPredictionResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.ResourceAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.List;

@Service
public class MlServiceClient {

        private static final Logger logger = LoggerFactory.getLogger(MlServiceClient.class);

        private final RestClient restClient;

        public MlServiceClient(
                        RestClient.Builder restClientBuilder,
                        MlServiceConfig mlServiceConfig) {

                SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();

                requestFactory.setConnectTimeout(
                                mlServiceConfig.connectTimeoutMs());

                requestFactory.setReadTimeout(
                                mlServiceConfig.readTimeoutMs());

                this.restClient = restClientBuilder
                                .baseUrl(mlServiceConfig.baseUrl())
                                .requestFactory(requestFactory)
                                .build();
        }

        public MlPredictionResponse predict(String url) {

                try {

                        logger.info("ML request started");

                        MlPredictionResponse response = restClient
                                        .post()
                                        .uri("/predict")
                                        .body(new PredictionRequest(url))
                                        .retrieve()
                                        .body(MlPredictionResponse.class);

                        if (response == null) {
                                throw new MlServiceException(
                                                "ML service returned an empty response.",
                                                MlServiceException.FailureType.MALFORMED_RESPONSE,
                                                null);
                        }

                        validateResponse(response);

                        return response;

                } catch (ResourceAccessException ex) {

                        if (isTimeout(ex)) {
                                logger.warn("ML service timed out");
                                throw new MlServiceException(
                                                "ML service response timed out.",
                                                MlServiceException.FailureType.TIMEOUT,
                                                ex);
                        }

                        logger.warn("ML service unavailable");
                        throw new MlServiceException(
                                        "AI analysis service is unavailable.",
                                        MlServiceException.FailureType.UNAVAILABLE,
                                        ex);

                } catch (RestClientException ex) {

                        logger.warn("ML service returned an unusable response");
                        throw new MlServiceException(
                                        "ML service returned an unusable response.",
                                        MlServiceException.FailureType.MALFORMED_RESPONSE,
                                        ex);
                }
        }

        public boolean isHealthy() {

                try {

                        restClient
                                        .get()
                                        .uri("/health")
                                        .retrieve()
                                        .toBodilessEntity();

                        return true;

                } catch (RestClientException ex) {

                        return false;
                }
        }

        private record PredictionRequest(String url) {
        }

        private void validateResponse(MlPredictionResponse response) {

                if (response.url() == null
                                || response.url().isBlank()
                                || response.risk_level() == null
                                || response.risk_level().isBlank()
                                || response.prediction() == null
                                || response.prediction().isBlank()
                                || response.decision() == null
                                || response.decision().isBlank()
                                || !Double.isFinite(response.phishing_probability())
                                || response.phishing_probability() < 0.0
                                || response.phishing_probability() > 1.0
                                || response.risk_score() < 0
                                || response.risk_score() > 100
                                || !Double.isFinite(response.threshold())
                                || response.threshold() < 0.0
                                || response.threshold() > 1.0
                                || !List.of(
                                                "SAFE",
                                                "LOW_RISK",
                                                "LOW RISK",
                                                "SUSPICIOUS",
                                                "HIGH_RISK",
                                                "HIGH RISK")
                                                .contains(response.risk_level())) {
                        throw new MlServiceException(
                                        "ML service returned an unusable response.",
                                        MlServiceException.FailureType.MALFORMED_RESPONSE,
                                        null);
                }
        }

        private boolean isTimeout(Throwable error) {

                Throwable current = error;
                while (current != null) {
                        if (current instanceof SocketTimeoutException
                                        || current instanceof IOException
                                                        && current.getMessage() != null
                                                        && current.getMessage().toLowerCase().contains("timed out")) {
                                return true;
                        }
                        current = current.getCause();
                }
                return false;
        }
}