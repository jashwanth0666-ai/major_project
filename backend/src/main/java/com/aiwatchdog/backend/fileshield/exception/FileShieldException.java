package com.aiwatchdog.backend.fileshield.exception;

import org.springframework.http.HttpStatus;

public class FileShieldException extends RuntimeException {
    private final HttpStatus status;
    private final String code;
    public FileShieldException(HttpStatus status, String code, String message) {
        super(message); this.status = status; this.code = code;
    }
    public HttpStatus status() { return status; }
    public String code() { return code; }
}
