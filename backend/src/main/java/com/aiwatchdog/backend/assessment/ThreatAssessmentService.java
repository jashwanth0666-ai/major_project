package com.aiwatchdog.backend.assessment;

import com.aiwatchdog.backend.dto.MlPredictionResponse;
import com.aiwatchdog.backend.dto.PageSignals;
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
import org.springframework.beans.factory.annotation.Autowired;

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
    private final UrlReputationService urlReputation;
    private final ConfiguredLocalDomainRuleService domainRules;
    private final AssessmentExplanationService explanationService;
    private final ObjectMapper mapper = new ObjectMapper();

    public ThreatAssessmentService(MlServiceClient ml, PolicyEngine policy, FileShieldService files,
                                   SecurityEventLogger events) {
        this(ml, policy, files, events, host -> UrlReputationResult.disabled(host),
                new ConfiguredLocalDomainRuleService("", ""), AssessmentExplanation::fallback);
    }

    @Autowired
    public ThreatAssessmentService(MlServiceClient ml, PolicyEngine policy, FileShieldService files,
                                   SecurityEventLogger events, UrlReputationService urlReputation,
                                   ConfiguredLocalDomainRuleService domainRules,
                                   AssessmentExplanationService explanationService) {
        this.ml = ml; this.policy = policy; this.files = files; this.events = events;
        this.urlReputation = urlReputation;
        this.domainRules = domainRules;
        this.explanationService = explanationService;
    }

    public ThreatAssessment assessUrl(String url) {
        return assessUrl(url, null, true);
    }

    public ThreatAssessment assessUrl(String url, PageSignals pageSignals) {
        return assessUrl(url, pageSignals, true);
    }

    /** Same assessment semantics as a navigation assessment, without an audit write for unvisited previews. */
    public ThreatAssessment previewUrl(String url) {
        return assessUrl(url, null, false);
    }

    public ThreatAssessment previewUrl(String url, PageSignals pageSignals) {
        return assessUrl(url, pageSignals, false);
    }

    private ThreatAssessment assessUrl(String url, PageSignals pageSignals, boolean persistResult) {
        if (url == null || url.isBlank()) throw new InvalidRequestException("URL must not be empty.");
        URI parsed;
        try {
            parsed = URI.create(url);
            if (!("http".equalsIgnoreCase(parsed.getScheme()) || "https".equalsIgnoreCase(parsed.getScheme()))
                    || UrlHostSignals.extractAsciiHost(parsed) == null)
                throw new InvalidRequestException("URL must be a valid HTTP or HTTPS URL.");
        } catch (IllegalArgumentException e) { throw new InvalidRequestException("URL must be a valid HTTP or HTTPS URL."); }
        Map<String,Object> source = new LinkedHashMap<>();
        List<String> explanations = new ArrayList<>(); List<String> errors = new ArrayList<>();
        List<String> pageReasons = pageSignals == null ? List.of() : pageSignals.securityReasons();
        if (pageSignals != null) source.put("browserPageSignals", pageSignals);
        Decision verdict; String status;
        MlPredictionResponse modelResult = null;
        try {
            MlPredictionResponse result = ml.predict(url);
            modelResult = result;
            source.put("urlModel", result);
            List<String> policyReasons = new ArrayList<>(result.reasons() == null ? List.of() : result.reasons());
            policyReasons.addAll(pageReasons);
            verdict = policy.evaluate(new PolicyRequest(result.url(), result.phishing_probability(),
                    result.risk_score(), result.risk_level(), result.prediction(), policyReasons));
            boolean unsupportedHighRisk = "HIGH RISK".equalsIgnoreCase(result.risk_level())
                    && "PHISHING".equalsIgnoreCase(result.prediction())
                    && (pageSignals == null || !pageSignals.hasCredentialRisk())
                    && (result.reasons() == null || result.reasons().isEmpty()
                    || result.reasons().stream().anyMatch(reason -> "No major URL-level warning indicators detected".equalsIgnoreCase(reason)));
            explanations.add(unsupportedHighRisk
                    ? "The model returned a high phishing score, but its URL checks found no corroborating warning indicators; policy requires review instead of blocking on the model alone."
                    : "Policy verdict follows the model risk category and corroborating evidence rules.");
            status = "COMPLETE";
        } catch (RuntimeException failure) {
            source.put("urlModel", Map.of("status", "UNAVAILABLE"));
            verdict = Decision.REVIEW; status = "PARTIAL";
            errors.add("URL prediction or policy evaluation failed; no safe verdict was inferred.");
        }
        String host = UrlHostSignals.extractAsciiHost(parsed);
        DomainRuleMatch domainRule = domainRules.lookup(host);
        source.put("localDomainRule", domainRule);
        if ("DENY".equals(domainRule.action())) {
            verdict = Decision.BLOCK;
            explanations.add("An operator-configured exact-host denylist rule matched; policy verdict is BLOCK.");
        } else if ("ALLOWLIST_EVIDENCE".equals(domainRule.action())) {
            explanations.add("The hostname matched an operator-configured allowlist entry; this is evidence only and does not override other detections.");
        }
        UrlHostSignals hostSignals = UrlHostSignals.inspect(host, parsed.getRawUserInfo() != null);
        source.put("urlHostSignals", hostSignals);
        if (!hostSignals.signals().isEmpty()) {
            explanations.add("Hostname heuristic signals are explainable indicators, not model attribution or a verdict.");
            hostSignals.signals().forEach(signal -> explanations.add(signal.explanation()));
        } else {
            explanations.add("No configured hostname deception heuristic matched; this does not establish that the URL is safe.");
        }
        UrlReputationResult reputation;
        if ("DENY".equals(domainRule.action())) {
            reputation = new UrlReputationResult("SKIPPED", "not-queried", host,
                    Instant.now().toString(), null, null, "Local denylist matched; external reputation lookup was skipped.");
        } else try { reputation = urlReputation.lookupUrl(redactUrl(url), host); }
        catch (RuntimeException failure) {
            reputation = new UrlReputationResult("UNAVAILABLE", "configured-url-provider", host,
                    Instant.now().toString(), null, null, "Provider lookup failed.");
        }
        source.put("urlReputation", reputation);
        switch (reputation.status()) {
            case "KNOWN_MALICIOUS" -> {
                verdict = Decision.BLOCK;
                explanations.add("The configured URL reputation provider reports this URL's host or path as known malicious; policy verdict is BLOCK.");
            }
            case "SUSPICIOUS" -> {
                verdict = elevate(verdict, Decision.WARN);
                explanations.add("The configured URL reputation provider reports suspicious hostname activity; policy is at least WARN.");
            }
            case "KNOWN_CLEAN" -> explanations.add("URL reputation provider reported this hostname as known clean; reputation evidence does not lower the model risk.");
            case "UNKNOWN" -> explanations.add("URL reputation has no record for this hostname; unknown is not clean.");
            case "SKIPPED" -> explanations.add("External reputation lookup was skipped because a local denylist rule already matched.");
            case "UNAVAILABLE" -> { explanations.add("URL reputation is unavailable; no safe verdict was inferred."); status = "PARTIAL"; errors.add("URL reputation provider is unavailable."); }
            default -> explanations.add("Optional URL reputation lookup is disabled.");
        }
        if (hostSignals.signals().stream().anyMatch(signal -> "HIGH".equalsIgnoreCase(signal.severity()))) {
            boolean modelAlsoHigh = modelResult != null
                    && modelResult.phishing_probability() >= modelResult.threshold();
            verdict = modelAlsoHigh ? Decision.BLOCK : elevate(verdict, Decision.WARN);
            explanations.add(modelAlsoHigh
                    ? "A high model score is corroborated by a high-severity hostname deception signal; policy verdict is BLOCK."
                    : "A high-severity hostname deception signal raises policy to at least WARN; heuristic signals are not proof of phishing.");
        } else if (modelResult != null
                && modelResult.phishing_probability() >= modelResult.threshold()
                && hostSignals.signals().stream().anyMatch(signal -> "MEDIUM".equalsIgnoreCase(signal.severity()))) {
            verdict = elevate(verdict, Decision.WARN);
            explanations.add("A medium-severity hostname mismatch corroborates the model score; policy is at least WARN.");
        }
        if (pageSignals != null) {
            pageReasons.forEach(reason -> explanations.add("Browser page signal: " + reason));
            if (pageSignals.hasCredentialRisk()) {
                verdict = elevate(verdict, Decision.WARN);
                explanations.add("Credential submission structure raises policy to at least WARN; the extension did not collect form values.");
            }
        }
        ThreatAssessment assessment = new ThreatAssessment(null, Instant.now().toString(), "URL", redactUrl(url), null,
                source, verdict.name(), status, explanations, errors, UUID.randomUUID().toString());
        assessment = enrichExplanation(assessment);
        return persistResult ? persist(assessment) : assessment;
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
        return persist(enrichExplanation(new ThreatAssessment(null, Instant.now().toString(), "FILE", subject,
                reputation.sha256(), sources, verdict.name(), status, explanation, errors, UUID.randomUUID().toString())));
    }

    private ThreatAssessment enrichExplanation(ThreatAssessment assessment) {
        try {
            AssessmentExplanation details = explanationService.explain(assessment);
            return new ThreatAssessment(assessment.assessmentId(), assessment.timestamp(), assessment.subjectType(),
                    assessment.subjectId(), assessment.sha256(), assessment.sources(), assessment.policyVerdict(),
                    assessment.status(), assessment.explanation(), assessment.errors(), assessment.correlationId(), details);
        } catch (RuntimeException ignored) {
            return assessment;
        }
    }

    private Decision elevate(Decision current, Decision minimum) {
        return decisionRank(current) >= decisionRank(minimum) ? current : minimum;
    }

    private int decisionRank(Decision decision) {
        return switch (decision) {
            case ALLOW -> 0;
            case REVIEW -> 1;
            case WARN -> 2;
            case BLOCK -> 3;
        };
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
                    "PARTIAL", assessment.explanation(), errors, assessment.correlationId(), assessment.explanationDetails());
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
                assessment.status(), assessment.explanation(), assessment.errors(), assessment.correlationId(),
                assessment.explanationDetails());
    }

    private String redactUrl(String raw) {
        try {
            URI uri = URI.create(raw);
            String host = UrlHostSignals.extractAsciiHost(uri);
            String path = uri.getPath() == null ? "" : uri.getPath();
            boolean sensitive = Arrays.stream(path.split("/"))
                    .anyMatch(segment -> SENSITIVE_PATH.matcher(segment).find()
                            || OPAQUE_PATH_SEGMENT.matcher(segment).matches());
            if (sensitive) path = "/";
            return new URI(uri.getScheme(), null, host, uri.getPort(), path, null, null).toASCIIString();
        }
        catch (Exception ignored) { return "[redacted URL]"; }
    }
}
