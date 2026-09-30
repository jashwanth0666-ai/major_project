package com.aiwatchdog.backend.monitor;

import com.aiwatchdog.backend.policy.RiskLevel;
import java.util.List;

public record RiskAssessment(int score, RiskLevel level, List<String> reasons) { }
