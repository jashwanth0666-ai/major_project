package com.aiwatchdog.backend.assessment;

import com.aiwatchdog.backend.logging.SecurityEvent;
import com.aiwatchdog.backend.logging.SecurityEventLogger;
import com.aiwatchdog.backend.policy.Decision;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.time.Instant;
import java.util.Map;

/** Stores human feedback linked to an assessment, without retaining a URL or page data. */
@RestController
@RequestMapping("/api/v1/threat-assessments")
public class ThreatFeedbackController {
    private final SecurityEventLogger events;
    private final SeenUrlFeedbackStore seenUrls;
    private final ObjectMapper mapper = new ObjectMapper();

    public ThreatFeedbackController(SecurityEventLogger events, SeenUrlFeedbackStore seenUrls) {
        this.events = events;
        this.seenUrls = seenUrls;
    }

    @PostMapping("/feedback")
    public ResponseEntity<Map<String, Boolean>> submit(@Valid @RequestBody ThreatFeedbackRequest request) {
        if ("FALSE_POSITIVE".equals(request.label()) && !seenUrls.markSafe(request.assessmentId(), request.correlationId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "This assessment is unavailable for exact-URL feedback.");
        }
        String details;
        try {
            details = mapper.writeValueAsString(Map.of("label", request.label()));
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("Feedback could not be serialized.", impossible);
        }
        events.logAssessment(new SecurityEvent(null, Instant.now(), null, null, null, null, null,
                Decision.REVIEW.name(), "URL_FEEDBACK", "FEEDBACK", request.assessmentId(),
                request.correlationId(), details));
        return ResponseEntity.ok(Map.of("accepted", true));
    }
}
