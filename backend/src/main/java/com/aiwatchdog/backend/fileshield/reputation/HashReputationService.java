package com.aiwatchdog.backend.fileshield.reputation;

public interface HashReputationService {
    HashReputation lookup(String sha256);
    default java.util.List<ReputationProviderStatus> providerStatuses() { return java.util.List.of(); }
}
