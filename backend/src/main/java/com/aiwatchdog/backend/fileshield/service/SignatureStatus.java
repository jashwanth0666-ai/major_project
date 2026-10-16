package com.aiwatchdog.backend.fileshield.service;

public enum SignatureStatus {
    VALID,
    INVALID,
    UNSIGNED,
    NOT_REQUESTED,
    INSPECTION_ERROR,
    UNSUPPORTED
}
