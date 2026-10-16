package com.aiwatchdog.backend.fileshield.dto;

import java.util.List;

public record DirectoryScanResponse(String directoryName, int discovered, int scanned, int failed,
                                   int rejected, int knownMalicious, int knownClean, int suspicious, int unknown,
                                   int lookupErrors, boolean limitReached, List<FileScanResponse> results) { }
