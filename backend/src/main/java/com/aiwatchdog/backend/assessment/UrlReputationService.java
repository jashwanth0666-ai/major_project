package com.aiwatchdog.backend.assessment;

public interface UrlReputationService {
    UrlReputationResult lookup(String host);
}
