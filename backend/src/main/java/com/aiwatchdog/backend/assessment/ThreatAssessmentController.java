package com.aiwatchdog.backend.assessment;

import com.aiwatchdog.backend.dto.AnalyzeRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/threat-assessments")
public class ThreatAssessmentController {
    private final ThreatAssessmentService service;
    public ThreatAssessmentController(ThreatAssessmentService service) { this.service = service; }

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
