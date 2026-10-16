package com.aiwatchdog.backend.fileshield.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/** Uses Microsoft's Get-AuthenticodeSignature read-only cmdlet; the target file is never loaded as code. */
@Component
public class AuthenticodeSignatureInspector {
    private static final long TIMEOUT_SECONDS = 5;
    private static final int MAX_OUTPUT_BYTES = 16_384;
    private static final String SCRIPT = ""
            + "$ErrorActionPreference='Stop'; "
            + "$s=Get-AuthenticodeSignature -LiteralPath $env:AIWD_SIGNATURE_PATH -ErrorAction Stop; "
            + "$o=@{status=[string]$s.Status; signer=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''}}; "
            + "$o | ConvertTo-Json -Compress";
    private final ObjectMapper mapper = new ObjectMapper();

    public SignatureInspection inspect(Path file) {
        if (!System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win"))
            return new SignatureInspection(SignatureStatus.UNSUPPORTED, null, "Authenticode inspection is available only on Windows.");
        String root = System.getenv("SystemRoot");
        if (root == null || root.isBlank())
            return new SignatureInspection(SignatureStatus.INSPECTION_ERROR, null, "Windows PowerShell could not be located.");
        Path powershell = Path.of(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(powershell.toString(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-");
            builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().put("AIWD_SIGNATURE_PATH", file.toAbsolutePath().normalize().toString());
            process = builder.start();
            try (var input = process.getOutputStream()) {
                input.write(SCRIPT.getBytes(StandardCharsets.UTF_8));
            }
            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new SignatureInspection(SignatureStatus.INSPECTION_ERROR, null, "Signature inspection timed out.");
            }
            byte[] output;
            try (var stream = process.getInputStream()) { output = stream.readNBytes(MAX_OUTPUT_BYTES + 1); }
            if (process.exitValue() != 0 || output.length == 0 || output.length > MAX_OUTPUT_BYTES)
                return new SignatureInspection(SignatureStatus.INSPECTION_ERROR, null, "Windows could not inspect the file signature.");
            var json = mapper.readTree(output);
            String status = json.path("status").asText("");
            String signer = bounded(json.path("signer").asText(null), 512);
            return switch (status) {
                case "Valid" -> new SignatureInspection(SignatureStatus.VALID, signer, "Windows reports a valid Authenticode signature.");
                case "NotSigned" -> new SignatureInspection(SignatureStatus.UNSIGNED, null, "No Authenticode signature was found; unsigned does not mean malicious.");
                case "HashMismatch", "NotTrusted", "PublisherMismatch" -> new SignatureInspection(SignatureStatus.INVALID, signer,
                        "Windows reports an invalid or untrusted Authenticode signature.");
                default -> new SignatureInspection(SignatureStatus.INSPECTION_ERROR, signer,
                        "Windows could not establish the Authenticode signature status (" + bounded(status, 80) + ").");
            };
        } catch (IOException | InterruptedException | RuntimeException exception) {
            if (process != null) process.destroyForcibly();
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            return new SignatureInspection(SignatureStatus.INSPECTION_ERROR, null, "Windows signature inspection is unavailable.");
        }
    }

    private String bounded(String value, int max) {
        if (value == null || value.isBlank()) return null;
        return value.length() <= max ? value : value.substring(0, max);
    }
}
