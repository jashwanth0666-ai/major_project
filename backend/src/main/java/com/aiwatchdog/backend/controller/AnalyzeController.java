package com.aiwatchdog.backend.controller;

import com.aiwatchdog.backend.dto.AnalyzeRequest;
import com.aiwatchdog.backend.dto.AnalyzeResponse;
import com.aiwatchdog.backend.service.AnalysisService;
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

    public AnalyzeController(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<AnalyzeResponse> analyze(
            @Valid @RequestBody AnalyzeRequest request) {

        AnalyzeResponse response = analysisService.analyze(request.url());

        return ResponseEntity.ok(response);
    }
}