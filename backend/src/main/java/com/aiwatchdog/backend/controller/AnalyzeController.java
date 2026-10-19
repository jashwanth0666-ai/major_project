package com.aiwatchdog.backend.controller;

import com.aiwatchdog.backend.dto.AnalyzeRequest;
import com.aiwatchdog.backend.dto.AnalyzeResponse;
import com.aiwatchdog.backend.service.AnalysisService;
import com.aiwatchdog.backend.assessment.ThreatAssessment;
import com.aiwatchdog.backend.assessment.ThreatAssessmentService;
import com.aiwatchdog.backend.dto.MlPredictionResponse;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class AnalyzeController {

    private final AnalysisService analysisService;
    private final ThreatAssessmentService threatAssessmentService;

    public AnalyzeController(AnalysisService analysisService) {
        this(analysisService, null);
    }

    @Autowired
    public AnalyzeController(AnalysisService analysisService, ThreatAssessmentService threatAssessmentService) {
        this.analysisService = analysisService;
        this.threatAssessmentService = threatAssessmentService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<AnalyzeResponse> analyze(
            @Valid @RequestBody AnalyzeRequest request) {

        AnalyzeResponse response = threatAssessmentService == null
                ? analysisService.analyze(request.url())
                : response(threatAssessmentService.assessUrl(request.url()));

        return ResponseEntity.ok(response);
    }

    /** Evaluates a search result without adding an unvisited destination to audit history. */
    @PostMapping("/analyze/preview")
    public ResponseEntity<AnalyzeResponse> preview(
            @Valid @RequestBody AnalyzeRequest request) {
        return ResponseEntity.ok(threatAssessmentService == null
                ? analysisService.preview(request.url())
                : response(threatAssessmentService.previewUrl(request.url())));
    }

    private AnalyzeResponse response(ThreatAssessment assessment) {
        Object modelSource = assessment.sources().get("urlModel");
        if (!(modelSource instanceof MlPredictionResponse model)) {
            throw new IllegalStateException("Unified URL assessment returned no model result.");
        }
        java.util.List<String> reasons = new java.util.ArrayList<>(assessment.explanation());
        if (model.reasons() != null) model.reasons().forEach(reason -> reasons.add("URL indicator: " + reason));
        Object submittedUrl = assessment.sources().get("submittedUrl");
        String displayUrl = submittedUrl instanceof String value ? value : model.url();
        return new AnalyzeResponse(displayUrl, model.phishing_probability(), model.risk_score(),
                model.risk_level(), model.prediction(), assessment.policyVerdict(), model.threshold(),
                reasons, assessment.assessmentId(), assessment.correlationId());
    }
}
