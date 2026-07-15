package com.dpi.extractor;

import java.util.Optional;

/**
 * Extracts the HTTP Host header from an unencrypted HTTP request.
 * Maps to HTTPHostExtractor in sni_extractor.h / sni_extractor.cpp.
 */
public class HTTPHostExtractor {

    private static final byte[][] HTTP_METHODS = {
        "GET ".getBytes(),
        "POST".getBytes(),
        "PUT ".getBytes(),
        "HEAD".getBytes(),
        "DELE".getBytes(),
        "PATC".getBytes(),
        "OPTI".getBytes()
    };

    /**
     * Check if the payload looks like an HTTP request.
     */
    public static boolean isHTTPRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        for (byte[] method : HTTP_METHODS) {
            if (offset + 4 <= payload.length &&
                payload[offset]     == method[0] &&
                payload[offset + 1] == method[1] &&
                payload[offset + 2] == method[2] &&
                payload[offset + 3] == method[3]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract the Host header value from an HTTP request.
     *
     * @param payload Raw TCP payload bytes.
     * @param offset  Start offset.
     * @param length  Number of available bytes from offset.
     * @return Host header value without port, or empty if not found.
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHTTPRequest(payload, offset, length)) return Optional.empty();

        int end = offset + length;

        // Search for "host:" (case-insensitive)
        for (int i = offset; i + 5 < end; i++) {
            int b0 = payload[i]     & 0xFF;
            int b1 = payload[i + 1] & 0xFF;
            int b2 = payload[i + 2] & 0xFF;
            int b3 = payload[i + 3] & 0xFF;
            int b4 = payload[i + 4] & 0xFF;

            boolean isH = (b0 == 'H' || b0 == 'h');
            boolean isO = (b1 == 'o' || b1 == 'O');
            boolean isS = (b2 == 's' || b2 == 'S');
            boolean isT = (b3 == 't' || b3 == 'T');
            boolean isColon = (b4 == ':');

            if (isH && isO && isS && isT && isColon) {
                // Skip "Host:" and optional whitespace
                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find end of line (\r or \n)
                int lineEnd = start;
                while (lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n') {
                    lineEnd++;
                }

                if (lineEnd > start) {
                    String host = new String(payload, start, lineEnd - start);
                    // Remove port if present ("example.com:8080" -> "example.com")
                    int colonPos = host.indexOf(':');
                    if (colonPos >= 0) {
                        host = host.substring(0, colonPos);
                    }
                    return Optional.of(host.trim());
                }
            }
        }

        return Optional.empty();
    }
}
