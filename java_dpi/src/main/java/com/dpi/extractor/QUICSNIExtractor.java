package com.dpi.extractor;

import java.util.Optional;

/**
 * Attempts to extract SNI from a QUIC Initial packet.
 * QUIC Initial packets embed a TLS Client Hello in CRYPTO frames.
 *
 * This is a simplified version that searches for the TLS Client Hello
 * pattern within the QUIC packet payload, mirroring the C++ implementation.
 *
 * Maps to QUICSNIExtractor in sni_extractor.h / sni_extractor.cpp.
 */
public class QUICSNIExtractor {

    /**
     * Check if this looks like a QUIC Initial packet (long header form).
     */
    public static boolean isQUICInitial(byte[] payload, int offset, int length) {
        if (length < 5) return false;
        // Long header form: high bit set
        return (payload[offset] & 0x80) != 0;
    }

    /**
     * Try to extract SNI from a QUIC packet by scanning for a TLS Client Hello.
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isQUICInitial(payload, offset, length)) return Optional.empty();

        int end = offset + length;

        // Scan for TLS Client Hello handshake type byte (0x01)
        // The SNI extractor needs at least 5 bytes before it (TLS record header)
        for (int i = offset; i + 50 < end; i++) {
            if ((payload[i] & 0xFF) == 0x01) { // Client Hello handshake type
                // Try SNI extraction starting 5 bytes earlier (TLS record header)
                int tryOffset = i - 5;
                if (tryOffset < offset) continue;
                int tryLength = end - tryOffset;
                Optional<String> result = SNIExtractor.extract(payload, tryOffset, tryLength);
                if (result.isPresent()) return result;
            }
        }

        return Optional.empty();
    }
}
