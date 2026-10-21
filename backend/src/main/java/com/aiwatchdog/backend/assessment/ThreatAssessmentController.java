package com.aiwatchdog.backend.assessment;

import com.aiwatchdog.backend.dto.AnalyzeRequest;
import com.aiwatchdog.backend.logging.SecurityEvent;
import com.aiwatchdog.backend.logging.SecurityEventRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/threat-assessments")
public class ThreatAssessmentController {
    private final ThreatAssessmentService service;
    private final SecurityEventRepository events;
    private final ObjectMapper mapper = new ObjectMapper();
    public ThreatAssessmentController(ThreatAssessmentService service, SecurityEventRepository events) {
        this.service = service;
        this.events = events;
    }

    @GetMapping("/{assessmentId}")
    public ResponseEntity<ThreatAssessment> getAssessment(@PathVariable UUID assessmentId) {
        SecurityEvent event = events.findAssessmentById(assessmentId.toString()).orElse(null);
        if (event == null || !"URL".equals(event.subjectType())) return ResponseEntity.notFound().build();
        try { return ResponseEntity.ok(mapper.readValue(event.detailsJson(), ThreatAssessment.class)); }
        catch (JsonProcessingException invalidRecord) {
            throw new IllegalStateException("Stored threat assessment could not be decoded.", invalidRecord);
        }
    }

    @PostMapping("/url")
    public ThreatAssessment assessUrl(@Valid @RequestBody AnalyzeRequest request) {
        return service.assessUrl(request.url(), request.pageSignals());
    }

    @PostMapping("/url/preview")
    public ThreatAssessment previewUrl(@Valid @RequestBody AnalyzeRequest request) {
        return service.previewUrl(request.url(), request.pageSignals());
    }

    @PostMapping("/file")
    public ThreatAssessment assessFile(@Valid @RequestBody ThreatAssessmentRequest request) {
        return service.assessFile(request.path());
    }
}
