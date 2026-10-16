package com.aiwatchdog.backend.fileshield.reputation;

import java.time.Instant;

public record ReputationProviderStatus(String provider, String state, String errorCategory, Instant lastCheckedAt) { }
