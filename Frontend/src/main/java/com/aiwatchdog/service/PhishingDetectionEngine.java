package com.aiwatchdog.service;

import com.aiwatchdog.model.AnalysisResult;

public interface PhishingDetectionEngine {
    AnalysisResult analyze(String url);
}
