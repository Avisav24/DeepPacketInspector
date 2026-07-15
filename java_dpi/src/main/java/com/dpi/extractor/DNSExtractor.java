package com.dpi.extractor;

import java.util.Optional;

/**
 * Extracts the queried domain name from a DNS request packet.
 * Maps to DNSExtractor in sni_extractor.h / sni_extractor.cpp.
 *
 * DNS Header (12 bytes):
 *   Transaction ID: 2 bytes
 *   Flags:          2 bytes  (bit 15 = QR: 0=query, 1=response)
 *   QDCOUNT:        2 bytes  (number of questions)
 *   ANCOUNT:        2 bytes
 *   NSCOUNT:        2 bytes
 *   ARCOUNT:        2 bytes
 * Question Section follows immediately.
 */
public class DNSExtractor {

    /**
     * Check if this is a DNS query (not a response).
     */
    public static boolean isDNSQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;
        // QR bit is bit 7 of the flags high byte (byte at offset+2)
        int flags = payload[offset + 2] & 0xFF;
        if ((flags & 0x80) != 0) return false; // It's a response

        // QDCOUNT (bytes 4-5) must be > 0
        int qdcount = SNIExtractor.readUint16BE(payload, offset + 4);
        return qdcount > 0;
    }

    /**
     * Extract the queried domain name from a DNS query.
     *
     * @param payload Raw UDP payload bytes.
     * @param offset  Start offset.
     * @param length  Number of bytes available.
     * @return The domain name (e.g., "www.google.com"), or empty.
     */
    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDNSQuery(payload, offset, length)) return Optional.empty();

        int end = offset + length;
        int pos = offset + 12; // Skip DNS header

        StringBuilder domain = new StringBuilder();

        while (pos < end) {
            int labelLen = payload[pos] & 0xFF;

            if (labelLen == 0) break; // End of domain name

            if (labelLen > 63) break; // Compression pointer or invalid

            pos++;
            if (pos + labelLen > end) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, pos, labelLen));
            pos += labelLen;
        }

        String result = domain.toString();
        return result.isEmpty() ? Optional.empty() : Optional.of(result);
    }
}
