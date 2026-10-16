package com.aiwatchdog.backend.fileshield.controller;

import com.aiwatchdog.backend.fileshield.dto.DirectoryScanRequest;
import com.aiwatchdog.backend.fileshield.dto.DirectoryScanResponse;
import com.aiwatchdog.backend.fileshield.dto.FileScanRequest;
import com.aiwatchdog.backend.fileshield.dto.FileScanResponse;
import com.aiwatchdog.backend.fileshield.config.FileShieldSettingsRequest;
import com.aiwatchdog.backend.fileshield.config.FileShieldSettingsResponse;
import com.aiwatchdog.backend.fileshield.config.FileShieldSettingsService;
import com.aiwatchdog.backend.fileshield.service.FileShieldService;
import com.aiwatchdog.backend.fileshield.service.FileQuarantineService;
import com.aiwatchdog.backend.fileshield.dto.QuarantineRequest;
import com.aiwatchdog.backend.fileshield.dto.RestoreQuarantinedFileRequest;
import com.aiwatchdog.backend.fileshield.dto.QuarantineOperationResult;
import com.aiwatchdog.backend.fileshield.dto.QuarantineHistoryResponse;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Path;

@RestController
@RequestMapping("/api/v1/file-shield")
public class FileShieldController {
    private final FileShieldService service;
    private final FileShieldSettingsService settings;
    private final FileQuarantineService quarantine;
    @Autowired
    public FileShieldController(FileShieldService service, FileShieldSettingsService settings, FileQuarantineService quarantine) {
        this.service = service;
        this.settings = settings;
        this.quarantine = quarantine;
    }
    public FileShieldController(FileShieldService service, FileShieldSettingsService settings) { this(service, settings, null); }

    @PostMapping("/scan")
    public FileScanResponse scan(@Valid @RequestBody FileScanRequest request) { return service.scanFile(Path.of(request.path())); }

    @PostMapping("/scan-directory")
    public DirectoryScanResponse scanDirectory(@Valid @RequestBody DirectoryScanRequest request) { return service.scanDirectory(Path.of(request.path())); }

    @GetMapping("/settings")
    public FileShieldSettingsResponse getSettings(HttpServletRequest request) {
        requireLocalRequest(request);
        return settings.get();
    }

    @PutMapping("/settings")
    public FileShieldSettingsResponse updateSettings(@RequestBody FileShieldSettingsRequest request,
                                                     HttpServletRequest httpRequest) {
        requireLocalRequest(httpRequest);
        try { return settings.update(request); }
        catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, exception.getMessage());
        }
        catch (IllegalStateException exception) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
        }
    }

    @GetMapping("/quarantine")
    public QuarantineHistoryResponse quarantineHistory(HttpServletRequest request) {
        requireLocalRequest(request);
        return quarantine.history();
    }

    @PostMapping("/quarantine")
    public QuarantineOperationResult quarantine(@Valid @RequestBody QuarantineRequest request, HttpServletRequest httpRequest) {
        requireLocalRequest(httpRequest);
        return quarantine.quarantine(request);
    }

    @PostMapping("/quarantine/{operationId}/restore")
    public QuarantineOperationResult restore(@org.springframework.web.bind.annotation.PathVariable String operationId,
                                              @RequestBody RestoreQuarantinedFileRequest request,
                                              HttpServletRequest httpRequest) {
        requireLocalRequest(httpRequest);
        return quarantine.restore(operationId, request);
    }

    private void requireLocalRequest(HttpServletRequest request) {
        String address = request.getRemoteAddr();
        if (!"127.0.0.1".equals(address) && !"::1".equals(address) && !"0:0:0:0:0:0:0:1".equals(address))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "File Shield administration is available only from this computer.");
    }
}
