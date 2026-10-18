# Static PE Analyzer

The FastAPI app exposes `POST http://127.0.0.1:8000/api/analyze-file` for local static analysis of `.exe` and `.dll` files. It uses `pefile` to parse bounded file bytes; it never executes or loads a binary, sends file data to another service, modifies the file, or changes the URL prediction pipeline.

## Install and configure

Install the API dependencies from the repository root:

```powershell
python -m pip install -r requirements-api.txt
```

PE analysis is unavailable until at least one approved root is configured. The paths use the platform path-list separator (`;` on Windows):

```powershell
$env:AI_WATCHDOG_PE_APPROVED_ROOTS = "$env:USERPROFILE\Downloads"
$env:AI_WATCHDOG_PE_MAX_FILE_SIZE_BYTES = '52428800'
python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
```

Initialize local API credentials from the repository root before starting FastAPI; see [local API credentials](../doc/RUNNING.md#local-api-credentials). The launch scripts do this automatically.

The default maximum size is 50 MiB. It can be configured from 1 byte through 200 MiB. The API listens on loopback as configured in `api/config.py`; keep it local because this API accepts local paths. Use narrow approved roots. A symlink or junction that resolves outside those roots is rejected. Paths must be absolute and may not contain `..` components.

## Request

```powershell
$serviceToken = (Get-Content "$env:APPDATA\AIWatchDog\auth\api-tokens.json" -Raw | ConvertFrom-Json).springToMl
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/analyze-file `
  -Headers @{ Authorization = "Bearer $serviceToken" } `
  -ContentType 'application/json' `
  -Body '{"path":"C:\\Users\\you\\Downloads\\sample.exe"}'
```

The request model accepts only the `path` field. Invalid request validation responses omit raw inputs so a submitted local path is not echoed. The response contains only a basename, not an absolute path or file contents.

## Response shape

An analyzed file returns JSON with these fields (values below illustrate the shape; the hash is represented by a placeholder):

```json
{
  "status": "ANALYZED",
  "file_name": "sample.exe",
  "sha256": "<64 lowercase hexadecimal characters>",
  "file_size_bytes": 1536,
  "pe_valid": true,
  "architecture": "x86_64",
  "section_count": 2,
  "sections": [
    {
      "name": ".text",
      "virtual_size": 512,
      "raw_size": 512,
      "entropy": 4.2,
      "readable": true,
      "writable": false,
      "executable": true,
      "characteristics": 1610612768
    }
  ],
  "imports": [{"dll": "KERNEL32.dll", "apis": ["ReadFile"]}],
  "sensitive_imports": [],
  "anomalies": [],
  "suspicious_indicators": [
    "No configured suspicious structural indicators were detected; this does not establish that the file is clean."
  ],
  "risk_score": 10,
  "risk_score_explanation": "Heuristic, not a calibrated probability of malware...",
  "error": null
}
```

`status` is one of `ANALYZED`, `INVALID_PE`, `REJECTED_PATH`, `UNSUPPORTED_FILE`, or `ANALYSIS_ERROR`. Errors have an `error` object with a stable `code` and safe message. Typical HTTP mappings are 200 for analyzed or invalid PE data, 403 for rejected paths, 404 for unavailable files, 409 for a file changed during reading, 413 for oversize files, 415 for unsupported extensions, and 500 for parser failures.

## Heuristic score

The score starts at 10 and adds each independent evidence group at most once:

| Evidence group | Points |
| --- | ---: |
| Any section is both writable and executable | +25 |
| Any section with at least 1 KiB of raw data has entropy at least 7.2 | +15 |
| One or more selected sensitive API imports are present | +15 |
| Any file-boundary, overlapping-section, or malformed-import-table anomaly | +20 |
| Entry point does not map to an executable section | +10 |

The sum is clamped to 0–100. A group contributes once regardless of the number of matching sections or imports, avoiding repeated counting of the same evidence type. A high-entropy section can be legitimate compressed data; sensitive APIs are also used by legitimate software. The score is not a verdict or calibrated probability. It has not been evaluated against a labeled malware dataset, and no accuracy claims are made. `UNKNOWN` or `ANALYZED` never means clean.

## Limits

- Only `.exe` and `.dll` paths are accepted; other formats are reported as unsupported.
- File bytes are read only after the configured size check and never exceed the configured limit plus one sentinel byte. File metadata is checked before and after reading to detect ordinary concurrent changes.
- Sections, import DLLs, and API names returned in JSON are capped to keep responses bounded. PE parsing remains best-effort for malformed structures.
- The analyzer extracts metadata only. It does not perform emulation, disassembly, signature matching, reputation lookup, policy enforcement, or automatic remediation.
- Symlink and junction escape checks use canonical path resolution. Filesystem redirection can still race with a local attacker between validation and open; this local prototype is not a hardened multi-user scanning service.
- The JavaFX client currently calls Spring Boot for File Shield operations. This endpoint is directly available on the local FastAPI service; no Spring proxy or JavaFX screen is added in this phase.

## Tests

From the repository root, with the virtual environment installed from `requirements-api.txt`:

```powershell
python -m unittest discover -s tests -v
```
