package com.aiwatchdog.backend.controller;

import com.aiwatchdog.backend.service.MlServiceException;
import com.aiwatchdog.backend.service.InvalidRequestException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.time.Instant;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MlServiceException.class)
    public ResponseEntity<Map<String, Object>> handleMlServiceException(
            MlServiceException ex) {

        HttpStatus status = switch (ex.failureType()) {
            case TIMEOUT -> HttpStatus.GATEWAY_TIMEOUT;
            case MALFORMED_RESPONSE -> HttpStatus.BAD_GATEWAY;
            case UNAVAILABLE -> HttpStatus.SERVICE_UNAVAILABLE;
        };

        Map<String, Object> body = Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "error", switch (ex.failureType()) {
                    case TIMEOUT -> "ML_SERVICE_TIMEOUT";
                    case MALFORMED_RESPONSE -> "ML_SERVICE_BAD_RESPONSE";
                    case UNAVAILABLE -> "ML_SERVICE_UNAVAILABLE";
                },
                "message", ex.getMessage());

        return ResponseEntity
                .status(status)
                .body(body);
    }

    @ExceptionHandler({
            InvalidRequestException.class,
            IllegalArgumentException.class,
            MethodArgumentNotValidException.class,
            ConstraintViolationException.class,
            HttpMessageNotReadableException.class
    })
    public ResponseEntity<Map<String, Object>> handleBadRequest(Exception ex) {
        return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Request is invalid.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpectedException(Exception ex) {
        return error(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Unexpected backend error.");
    }

    private ResponseEntity<Map<String, Object>> error(
            HttpStatus status,
            String error,
            String message) {
        return ResponseEntity.status(status).body(Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "error", error,
                "message", message));
    }
}