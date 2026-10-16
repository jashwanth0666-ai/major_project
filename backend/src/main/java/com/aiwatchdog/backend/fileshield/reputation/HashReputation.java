package com.aiwatchdog.backend.fileshield.reputation;

import com.aiwatchdog.backend.fileshield.model.ReputationStatus;

public record HashReputation(ReputationStatus status, String source, String description) { }
