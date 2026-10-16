package com.aiwatchdog.backend.fileshield.service;

public record SignatureInspection(SignatureStatus status, String signerSubject, String message) { }
