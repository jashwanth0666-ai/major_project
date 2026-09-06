package com.aiwatchdog.backend.service;

public class MlServiceException extends RuntimeException {

    public enum FailureType {
        UNAVAILABLE,
        TIMEOUT,
        MALFORMED_RESPONSE
    }

    private final FailureType failureType;

    public MlServiceException(String message) {
        this(message, FailureType.UNAVAILABLE, null);
    }

    public MlServiceException(String message, Throwable cause) {
        this(message, FailureType.UNAVAILABLE, cause);
    }

    public MlServiceException(
            String message,
            FailureType failureType,
            Throwable cause) {
        super(message, cause);
        this.failureType = failureType;
    }

    public FailureType failureType() {
        return failureType;
    }
}