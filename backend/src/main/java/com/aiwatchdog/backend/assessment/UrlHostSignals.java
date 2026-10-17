package com.aiwatchdog.backend.assessment;

import java.net.IDN;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;

/** Explainable hostname-only heuristics. These signals are not a probability or verdict. */
public record UrlHostSignals(String status, String host, String checkedAt, List<Signal> signals) {
    public UrlHostSignals { signals = signals == null ? List.of() : List.copyOf(signals); }

    public static UrlHostSignals inspect(String host, boolean hasUserInfo) {
        String ascii = host == null ? "" : host.toLowerCase(Locale.ROOT);
        List<Signal> found = new ArrayList<>();
        if (hasUserInfo) found.add(new Signal("USERINFO_PRESENT", "MEDIUM",
                "The URL contains user information before the host, which can obscure the destination."));
        if (ascii.startsWith("[") && ascii.endsWith("]")) {
            return new UrlHostSignals("COMPLETE", ascii, Instant.now().toString(), found);
        }
        String clean = ascii.endsWith(".") ? ascii.substring(0, ascii.length() - 1) : ascii;
        String[] labels = clean.split("\\.");
        if (labels.length > 5) found.add(new Signal("DEEP_SUBDOMAIN_CHAIN", "LOW",
                "The hostname has more than five labels; inspect the registrable domain carefully."));
        boolean idn = false;
        boolean confusableMix = false;
        for (String label : labels) {
            if (label.startsWith("xn--")) idn = true;
            String unicode;
            try { unicode = IDN.toUnicode(label); }
            catch (RuntimeException invalid) { continue; }
            EnumSet<Character.UnicodeScript> scripts = EnumSet.noneOf(Character.UnicodeScript.class);
            unicode.codePoints().forEach(cp -> {
                Character.UnicodeScript script = Character.UnicodeScript.of(cp);
                if (script != Character.UnicodeScript.COMMON && script != Character.UnicodeScript.INHERITED
                        && script != Character.UnicodeScript.UNKNOWN) scripts.add(script);
            });
            if (scripts.contains(Character.UnicodeScript.LATIN)
                    && (scripts.contains(Character.UnicodeScript.GREEK)
                    || scripts.contains(Character.UnicodeScript.CYRILLIC))) confusableMix = true;
        }
        if (idn) found.add(new Signal("IDN_PUNYCODE", "LOW",
                "The hostname uses an internationalized domain label; inspect its displayed Unicode form."));
        if (confusableMix) found.add(new Signal("MIXED_CONFUSABLE_SCRIPT", "HIGH",
                "A hostname label mixes Latin with Greek or Cyrillic characters that can resemble Latin letters."));
        return new UrlHostSignals("COMPLETE", clean, Instant.now().toString(), found);
    }

    /** Extracts and validates the authority host, including Unicode IDNs that URI.getHost() rejects. */
    public static String extractAsciiHost(java.net.URI uri) {
        String authority = uri.getRawAuthority();
        if (authority == null || authority.isBlank()) return null;
        int at = authority.lastIndexOf('@');
        String value = at >= 0 ? authority.substring(at + 1) : authority;
        if (value.startsWith("[")) {
            int end = value.indexOf(']');
            if (end < 0 || (end + 1 < value.length() && !value.substring(end + 1).matches(":\\d{1,5}"))) return null;
            return value.substring(0, end + 1).toLowerCase(Locale.ROOT);
        }
        int colon = value.lastIndexOf(':');
        if (colon >= 0) {
            if (!value.substring(colon + 1).matches("\\d{1,5}")) return null;
            value = value.substring(0, colon);
        }
        try {
            String ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            if (ascii.isBlank() || ascii.length() > 253) return null;
            return ascii;
        } catch (IllegalArgumentException invalid) { return null; }
    }

    public record Signal(String code, String severity, String explanation) { }
}
