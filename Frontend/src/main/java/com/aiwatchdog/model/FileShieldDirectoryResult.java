package com.aiwatchdog.model;

import java.util.List;

/** Mirrors the bounded Spring directory scan response. */
public record FileShieldDirectoryResult(
        String directoryName,
        int discovered,
        int scanned,
        int failed,
        int rejected,
        int knownMalicious,
        int knownClean,
        int suspicious,
        int unknown,
        int lookupErrors,
        boolean limitReached,
        List<FileShieldScanResult> results) { }
