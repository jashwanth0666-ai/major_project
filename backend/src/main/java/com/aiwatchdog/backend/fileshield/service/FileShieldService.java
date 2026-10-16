package com.aiwatchdog.backend.fileshield.service;

import com.aiwatchdog.backend.fileshield.dto.DirectoryScanResponse;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;

import java.nio.file.Path;

public interface FileShieldService {
    FileScanResponse scanFile(Path path);
    /** Continuous monitoring is bounded and skips process-per-file Authenticode inspection. */
    default FileScanResponse scanFileForMonitoring(Path path) { return scanFile(path); }
    DirectoryScanResponse scanDirectory(Path path);
}
