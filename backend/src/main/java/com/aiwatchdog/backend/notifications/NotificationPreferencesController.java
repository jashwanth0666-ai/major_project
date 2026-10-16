package com.aiwatchdog.backend.notifications;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/notifications/preferences")
public class NotificationPreferencesController {
    private final NotificationPreferencesService service;

    public NotificationPreferencesController(NotificationPreferencesService service) {
        this.service = service;
    }

    @GetMapping
    public NotificationPreferences get(HttpServletRequest request) {
        requireLocalRequest(request);
        return service.get();
    }

    @PutMapping
    public NotificationPreferences update(@RequestBody NotificationPreferences preferences,
                                          HttpServletRequest request) {
        requireLocalRequest(request);
        try { return service.update(preferences); }
        catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, exception.getMessage());
        }
        catch (IllegalStateException exception) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
        }
    }

    private void requireLocalRequest(HttpServletRequest request) {
        String address = request.getRemoteAddr();
        if (!"127.0.0.1".equals(address) && !"::1".equals(address)
                && !"0:0:0:0:0:0:0:1".equals(address)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Notification preferences can only be changed from this computer.");
        }
    }
}
