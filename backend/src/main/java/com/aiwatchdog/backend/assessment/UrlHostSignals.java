package com.aiwatchdog.backend.assessment;

import java.net.IDN;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Explainable hostname-only heuristics. These signals are not a probability or verdict. */
public record UrlHostSignals(String status, String host, String checkedAt, List<Signal> signals) {
    private static final Map<String, Set<String>> OFFICIAL_BRAND_ROOTS = Map.ofEntries(
            Map.entry("google", Set.of("google.com", "google.co.uk", "google.ca", "google.com.au", "google.co.in")),
            Map.entry("microsoft", Set.of("microsoft.com", "microsoft.co.uk", "microsoft.ca", "microsoft.com.au")),
            Map.entry("apple", Set.of("apple.com", "apple.co.uk", "apple.ca", "apple.com.au")),
            Map.entry("amazon", Set.of("amazon.com", "amazon.co.uk", "amazon.ca", "amazon.com.au", "amazon.in")),
            Map.entry("paypal", Set.of("paypal.com", "paypal.co.uk", "paypal.ca", "paypal.com.au")),
            Map.entry("facebook", Set.of("facebook.com")),
            Map.entry("instagram", Set.of("instagram.com")),
            Map.entry("netflix", Set.of("netflix.com")),
            Map.entry("github", Set.of("github.com")),
            Map.entry("dropbox", Set.of("dropbox.com")),
            Map.entry("adobe", Set.of("adobe.com")),
            Map.entry("steam", Set.of("steampowered.com", "steamcommunity.com")),
            Map.entry("roblox", Set.of("roblox.com")),
            Map.entry("whatsapp", Set.of("whatsapp.com")),
            Map.entry("openai", Set.of("openai.com")));
    private static final Set<String> MULTI_LABEL_SUFFIXES = Set.of(
            "co.uk", "org.uk", "com.au", "net.au", "co.in", "com.br", "co.nz", "com.sg", "co.jp");

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
        inspectBrandLookalikes(clean, found);
        return new UrlHostSignals("COMPLETE", clean, Instant.now().toString(), found);
    }

    private static void inspectBrandLookalikes(String host, List<Signal> found) {
        String[] labels = host.split("\\.");
        if (labels.length < 2) return;
        String suffix = labels.length >= 3
                ? labels[labels.length - 2] + "." + labels[labels.length - 1] : labels[labels.length - 1];
        int sldIndex = MULTI_LABEL_SUFFIXES.contains(suffix) ? labels.length - 3 : labels.length - 2;
        if (sldIndex < 0) return;
        String registrableLabel = labels[sldIndex];
        String root = String.join(".", java.util.Arrays.copyOfRange(labels, sldIndex, labels.length));
        for (Map.Entry<String, Set<String>> brand : OFFICIAL_BRAND_ROOTS.entrySet()) {
            if (brand.getValue().stream().anyMatch(domain -> host.equals(domain) || host.endsWith("." + domain))) continue;
            String normalized = registrableLabel.replace("-", "");
            if (normalized.equals(brand.getKey()) || editDistanceAtMostOne(normalized, brand.getKey())) {
                found.add(new Signal("BRAND_LOOKALIKE_DOMAIN", "HIGH",
                        "The registrable domain closely resembles the well-known brand " + brand.getKey() + "."));
                return;
            }
            for (int i = 0; i < sldIndex; i++) {
                if (labels[i].equals(brand.getKey())) {
                    found.add(new Signal("BRAND_NAME_IN_SUBDOMAIN", "MEDIUM",
                            "A well-known brand name appears in a subdomain, while the registrable domain is different."));
                    return;
                }
            }
            if (registrableLabel.startsWith(brand.getKey() + "-")
                    || registrableLabel.endsWith("-" + brand.getKey())) {
                found.add(new Signal("BRAND_NAME_IN_DOMAIN", "MEDIUM",
                        "The registrable domain combines a well-known brand name with other words."));
                return;
            }
        }
    }

    private static boolean editDistanceAtMostOne(String left, String right) {
        if (left.equals(right) || Math.abs(left.length() - right.length()) > 1) return false;
        int i = 0, j = 0, edits = 0;
        while (i < left.length() && j < right.length()) {
            if (left.charAt(i) == right.charAt(j)) { i++; j++; continue; }
            if (++edits > 1) return false;
            if (left.length() > right.length()) i++;
            else if (right.length() > left.length()) j++;
            else { i++; j++; }
        }
        return edits + (i < left.length() || j < right.length() ? 1 : 0) <= 1;
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
