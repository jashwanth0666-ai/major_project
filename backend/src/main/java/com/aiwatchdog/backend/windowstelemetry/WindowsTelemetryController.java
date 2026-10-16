package com.aiwatchdog.backend.windowstelemetry;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/windows-telemetry")
public class WindowsTelemetryController {
    private final WindowsTelemetrySettingsService settings;
    private final WindowsSecurityTelemetryCollector collector;

    public WindowsTelemetryController(WindowsTelemetrySettingsService settings,
                                     WindowsSecurityTelemetryCollector collector) {
        this.settings = settings;
        this.collector = collector;
    }

    @GetMapping("/settings")
    public WindowsTelemetrySettingsResponse getSettings(HttpServletRequest request) {
        requireLocalRequest(request);
        return settings.get();
    }

    @PutMapping("/settings")
    public WindowsTelemetrySettingsResponse updateSettings(@RequestBody WindowsTelemetrySettingsRequest body,
                                                            HttpServletRequest request) {
        requireLocalRequest(request);
        try { return settings.update(body); }
        catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, exception.getMessage());
        }
        catch (IllegalStateException exception) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
        }
    }

    @GetMapping("/health")
    public WindowsTelemetryHealth health(HttpServletRequest request) {
        requireLocalRequest(request);
        return collector.getHealth();
    }

    private void requireLocalRequest(HttpServletRequest request) {
        String address = request.getRemoteAddr();
        if (!"127.0.0.1".equals(address) && !"::1".equals(address)
                && !"0:0:0:0:0:0:0:1".equals(address)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Windows telemetry settings and status are available only on this computer.");
        }
    }
}
