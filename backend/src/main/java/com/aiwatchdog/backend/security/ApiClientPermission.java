package com.aiwatchdog.backend.security;

import java.util.List;

public record ApiClientPermission(boolean configured, List<String> permissions) {
    public ApiClientPermission { permissions = permissions == null ? List.of() : List.copyOf(permissions); }
}
