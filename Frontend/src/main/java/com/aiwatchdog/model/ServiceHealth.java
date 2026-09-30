package com.aiwatchdog.model;

public record ServiceHealth(String springBoot, String mlService, int httpStatus) {
    public boolean isBackendAvailable() { return "UP".equalsIgnoreCase(springBoot); }
    public boolean isMlAvailable() { return "UP".equalsIgnoreCase(mlService); }
    public boolean isFullyAvailable() { return isBackendAvailable() && isMlAvailable(); }
}
