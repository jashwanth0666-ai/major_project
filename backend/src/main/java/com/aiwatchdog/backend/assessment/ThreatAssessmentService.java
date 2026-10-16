package com.aiwatchdog.backend.assessment;

import com.aiwatchdog.backend.dto.MlPredictionResponse;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import com.aiwatchdog.backend.fileshield.service.FileShieldService;
import com.aiwatchdog.backend.logging.SecurityEvent;
import com.aiwatchdog.backend.logging.SecurityEventLogger;
import com.aiwatchdog.backend.policy.Decision;
import com.aiwatchdog.backend.policy.PolicyEngine;
import com.aiwatchdog.backend.policy.PolicyRequest;
import com.aiwatchdog.backend.service.InvalidRequestException;
import com.aiwatchdog.backend.service.MlServiceClient;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class ThreatAssessmentService {
    private static final Pattern SENSITIVE_PATH = Pattern.compile(
            "(?i)(token|session|password|secret|credential|access[_-]?key|auth[_-]?code)");
    private static final Pattern OPAQUE_PATH_SEGMENT = Pattern.compile("[A-Za-z0-9_-]{32,}");
    private final MlServiceClient ml;
    private final PolicyEngine policy;
    private final FileShieldService files;
    private final SecurityEventLogger events;
    private final ObjectMapper mapper = new ObjectMapper();

    public ThreatAssessmentService(MlServiceClient ml, PolicyEngine policy, FileShieldService files,
                                   SecurityEventLogger events) {
        this.ml = ml; this.policy = policy; this.files = files; this.events = events;
    }

    public ThreatAssessment assessUrl(String url) {
        if (url == null || url.isBlank()) throw new InvalidRequestException("URL must not be empty.");
        try {
            URI parsed = URI.create(url);
            if (!("http".equalsIgnoreCase(parsed.getScheme()) || "https".equalsIgnoreCase(parsed.getScheme()))
                    || parsed.getHost() == null) throw new InvalidRequestException("URL must be a valid HTTP or HTTPS URL.");
        } catch (IllegalArgumentException e) { throw new InvalidRequestException("URL must be a valid HTTP or HTTPS URL."); }
        Map<String,Object> source = new LinkedHashMap<>();
        List<String> explanations = new ArrayList<>(); List<String> errors = new ArrayList<>();
        Decision verdict; String status;
        try {
            MlPredictionResponse result = ml.predict(url);
            source.put("urlModel", result);
            verdict = policy.evaluate(new PolicyRequest(result.url(), result.phishing_probability(),
                    result.risk_score(), result.risk_level(), result.prediction()));
            explanations.add("Policy verdict follows the existing model risk category and policy mapping.");
            status = "COMPLETE";
        } catch (RuntimeException failure) {
            source.put("urlModel", Map.of("status", "UNAVAILABLE"));
            verdict = Decision.REVIEW; status = "PARTIAL";
            errors.add("URL prediction or policy evaluation failed; no safe verdict was inferred.");
        }
        return persist(new ThreatAssessment(null, Instant.now().toString(), "URL", redactUrl(url), null,
                source, verdict.name(), status, explanations, errors, UUID.randomUUID().toString()));
    }

    public ThreatAssessment assessFile(String path) {
        if (path == null || path.isBlank()) throw new InvalidRequestException("File path must not be empty.");
        FileScanResponse reputation = files.scanFile(java.nio.file.Path.of(path));
        Map<String,Object> sources = new LinkedHashMap<>(); sources.put("fileReputation", reputation);
        List<String> explanation = new ArrayList<>(); List<String> errors = new ArrayList<>();
        Decision verdict;
        switch (reputation.reputationStatus()) {
            case KNOWN_MALICIOUS -> { verdict = Decision.BLOCK; explanation.add("SHA-256 matched a configured known-malicious reputation source."); }
            case KNOWN_CLEAN -> { verdict = Decision.ALLOW; explanation.add("SHA-256 matched a configured known-clean reputation source."); }
            case SUSPICIOUS -> { verdict = Decision.WARN; explanation.add("A configured reputation source reported suspicious indicators; this is not a malware verdict."); }
            case UNKNOWN -> { verdict = Decision.REVIEW; explanation.add("No reputation record exists; unknown is not clean."); }
            case LOOKUP_ERROR -> { verdict = Decision.REVIEW; errors.add("Reputation lookup failed."); explanation.add("Reputation is unavailable; no safe verdict was inferred."); }
            default -> { verdict = Decision.REVIEW; errors.add("File scan returned no usable reputation result."); }
        }
        String status = reputation.scanStatus().name().equals("COMPLETED") ? "COMPLETE" : "PARTIAL";
        JsonNode pe;
        try {
            pe = ml.analyzeFile(path);
            // Return JSON-native maps so Spring's configured HTTP mapper preserves the analyzer fields.
            sources.put("staticPe", mapper.convertValue(pe, Object.class));
            String peStatus = pe.path("status").asText("ANALYSIS_ERROR");
            if (!"ANALYZED".equals(peStatus)) {
                errors.add("Static PE analysis: " + peStatus + (pe.path("error").path("code").isMissingNode()
                        ? "" : " (" + pe.path("error").path("code").asText() + ")"));
                status = "PARTIAL";
            } else if (pe.path("risk_score").isNumber() && pe.path("risk_score").asInt() >= 50) {
                explanation.add("PE structural indicators warrant review; the heuristic score is not a malware probability.");
                if (verdict == Decision.ALLOW) verdict = Decision.REVIEW;
            } else {
                explanation.add("PE structural analysis completed; its heuristic score is kept separate from reputation.");
            }
            if (pe.path("sha256").isTextual() && reputation.sha256() != null
                    && !reputation.sha256().equalsIgnoreCase(pe.path("sha256").asText())) {
                errors.add("File changed between reputation and PE analysis; results may describe different bytes.");
                status = "PARTIAL"; verdict = Decision.REVIEW;
            }
        } catch (RuntimeException failure) {
            sources.put("staticPe", Map.of("status", "UNAVAILABLE"));
            errors.add("Static PE analysis is unavailable."); status = "PARTIAL";
            if (verdict == Decision.ALLOW) verdict = Decision.REVIEW;
        }
        String subject = reputation.sha256() == null ? "unavailable" : reputation.sha256();
        if (errors.isEmpty() && reputation.scanStatus().name().equals("COMPLETED")) status = "COMPLETE";
        return persist(new ThreatAssessment(null, Instant.now().toString(), "FILE", subject,
                reputation.sha256(), sources, verdict.name(), status, explanation, errors, UUID.randomUUID().toString()));
    }

    private ThreatAssessment persist(ThreatAssessment assessment) {
        String json;
        try { json = mapper.writeValueAsString(auditSafeCopy(assessment)); }
        catch (JsonProcessingException e) { throw new IllegalStateException("Assessment could not be serialized for audit.", e); }
        String subjectId = assessment.sha256() != null ? assessment.sha256() : assessment.subjectId();
        try {
            events.logAssessment(new SecurityEvent(null, Instant.parse(assessment.timestamp()), null, null, null, null, null,
                    assessment.policyVerdict(), "THREAT_ASSESSMENT", assessment.subjectType(), subjectId,
                    assessment.correlationId(), json));
            return assessment;
        } catch (RuntimeException failure) {
            List<String> errors = new ArrayList<>(assessment.errors());
            errors.add("Assessment was produced, but its audit event could not be persisted.");
            return new ThreatAssessment(assessment.assessmentId(), assessment.timestamp(), assessment.subjectType(),
                    assessment.subjectId(), assessment.sha256(), assessment.sources(), assessment.policyVerdict(),
                    "PARTIAL", assessment.explanation(), errors, assessment.correlationId());
        }
    }

    private ThreatAssessment auditSafeCopy(ThreatAssessment assessment) {
        Map<String, Object> safeSources = new LinkedHashMap<>(assessment.sources());
        Object model = safeSources.get("urlModel");
        if (model instanceof MlPredictionResponse result) {
            safeSources.put("urlModel", new MlPredictionResponse(redactUrl(result.url()),
                    result.phishing_probability(), result.risk_score(), result.risk_level(),
                    result.prediction(), result.threshold(), result.reasons()));
        }
        return new ThreatAssessment(assessment.assessmentId(), assessment.timestamp(), assessment.subjectType(),
                assessment.subjectId(), assessment.sha256(), safeSources, assessment.policyVerdict(),
                assessment.status(), assessment.explanation(), assessment.errors(), assessment.correlationId());
    }

    private String redactUrl(String raw) {
        try {
            URI uri = URI.create(raw);
            String path = uri.getPath() == null ? "" : uri.getPath();
            boolean sensitive = Arrays.stream(path.split("/"))
                    .anyMatch(segment -> SENSITIVE_PATH.matcher(segment).find()
                            || OPAQUE_PATH_SEGMENT.matcher(segment).matches());
            if (sensitive) path = "/";
            return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), path, null, null).toASCIIString();
        }
        catch (Exception ignored) { return "[redacted URL]"; }
    }
}
