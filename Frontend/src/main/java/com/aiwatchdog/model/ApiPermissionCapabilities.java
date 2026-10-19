package com.aiwatchdog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ApiPermissionCapabilities(ApiClientPermission desktop, ApiClientPermission browserExtension,
        String enforcement, String windowsPrivileges) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ApiClientPermission(boolean configured, List<String> permissions) { }
}
