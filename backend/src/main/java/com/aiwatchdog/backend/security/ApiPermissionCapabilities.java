package com.aiwatchdog.backend.security;

public record ApiPermissionCapabilities(ApiClientPermission desktop, ApiClientPermission browserExtension,
        String enforcement, String windowsPrivileges) { }
