package com.aiwatchdog.backend.fileshield.service;

import java.io.IOException;
import java.nio.file.Path;

public interface Sha256Scanner {
    String sha256(Path file) throws IOException;
    default String sha256(Path file, long maximumBytes) throws IOException {
        if (java.nio.file.Files.size(file) > maximumBytes) throw new IOException("File exceeds the configured hash limit.");
        return sha256(file);
    }
}
