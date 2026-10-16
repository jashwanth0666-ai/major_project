package com.aiwatchdog.backend.fileshield.service;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.LinkOption;
import java.nio.channels.Channels;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Component
public class DefaultSha256Scanner implements Sha256Scanner {
    private static final int BUFFER_SIZE = 64 * 1024;

    @Override
    public String sha256(Path file) throws IOException {
        return sha256(file, Long.MAX_VALUE);
    }

    @Override
    public String sha256(Path file, long maximumBytes) throws IOException {
        if (maximumBytes < 0) throw new IllegalArgumentException("Maximum hash size must not be negative.");
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
        byte[] buffer = new byte[BUFFER_SIZE];
        long total = 0;
        try (InputStream input = Channels.newInputStream(Files.newByteChannel(
                file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (total > maximumBytes - count) throw new IOException("File exceeds the configured hash limit.");
                total += count;
                digest.update(buffer, 0, count);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
