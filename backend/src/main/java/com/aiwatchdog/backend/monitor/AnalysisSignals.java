package com.aiwatchdog.backend.monitor;

import java.util.List;

public record AnalysisSignals(int score, List<String> reasons) { }
