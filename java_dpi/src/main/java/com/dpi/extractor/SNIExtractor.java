package com.dpi.extractor;

import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) from a TLS Client Hello packet.
 *
 * TLS Client Hello Structure:
 *   Record Layer (5 bytes):
 *     Content Type: 0x16 (Handshake)
 *     Version:      0x0301 / 0x0303
 *     Length:       2 bytes
 *   Handshake Layer:
 *     Type:         0x01 (Client Hello)
 *     Length:       3 bytes (24-bit)
 *     Client Version: 2 bytes
 *     Random:       32 bytes
 *     Session ID Len: 1 byte
 *     Session ID:   variable
 *     Cipher Suites Len: 2 bytes
 *     Cipher Suites: variable
 *     Compression Methods Len: 1 byte
 *     Compression Methods: variable
 *     Extensions Len: 2 bytes
 *     Extensions: variable
 *       SNI Extension (type 0x0000):
 *         SNI List Length: 2 bytes
 *         SNI Type:        1 byte (0x00 = hostname)
 *         SNI Length:      2 bytes
 *         SNI Value:       the hostname string
 *
 * Maps to SNIExtractor in sni_extractor.h / sni_extractor.cpp.
 */
public class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE  = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO  = 0x01;
    private static final int EXTENSION_SNI           = 0x0000;
    private static final int SNI_TYPE_HOSTNAME       = 0x00;

    /**
     * Check if the payload looks like a TLS Client Hello.
     *
     * @param payload Raw TCP payload bytes.
     * @param offset  Start offset in the array.
     * @param length  Number of bytes to examine.
     */
    public static boolean isTLSClientHello(byte[] payload, int offset, int length) {
        if (length < 9) return false;
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        int version = readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;

        int recordLength = readUint16BE(payload, offset + 3);
        if (recordLength > length - 5) return false;

        if ((payload[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;

        return true;
    }

    /**
     * Extract the SNI hostname from a TLS Client Hello.
     *
     * @param payload Raw TCP payload bytes.
     * @param offset  Start offset in the array.
     * @param length  Number of bytes available from offset.
     * @return The SNI hostname, or empty if not found / not a TLS Client Hello.
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTLSClientHello(payload, offset, length)) {
            return Optional.empty();
        }

        int end = offset + length;
        int pos = offset;

        // Skip TLS record header (5 bytes)
        pos += 5;

        // Skip handshake header: type(1) + length(3) = 4 bytes
        if (pos + 4 > end) return Optional.empty();
        pos += 4;

        // Skip Client Hello: client_version(2) + random(32) = 34 bytes
        pos += 34;

        // Session ID
        if (pos >= end) return Optional.empty();
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Cipher suites
        if (pos + 2 > end) return Optional.empty();
        int cipherSuitesLen = readUint16BE(payload, pos);
        pos += 2 + cipherSuitesLen;

        // Compression methods
        if (pos >= end) return Optional.empty();
        int compressionLen = payload[pos] & 0xFF;
        pos += 1 + compressionLen;

        // Extensions length
        if (pos + 2 > end) return Optional.empty();
        int extensionsLen = readUint16BE(payload, pos);
        pos += 2;

        int extensionsEnd = pos + extensionsLen;
        if (extensionsEnd > end) extensionsEnd = end; // Truncated but try anyway

        // Scan extensions for SNI (type 0x0000)
        while (pos + 4 <= extensionsEnd) {
            int extType   = readUint16BE(payload, pos);
            int extLength = readUint16BE(payload, pos + 2);
            pos += 4;

            if (pos + extLength > extensionsEnd) break;

            if (extType == EXTENSION_SNI) {
                // SNI extension structure:
                //   SNI List Length (2 bytes)
                //   SNI Type        (1 byte) — 0x00 = hostname
                //   SNI Length      (2 bytes)
                //   SNI Value       (variable)
                if (extLength < 5) break;

                // sniListLength is at pos, but we don't need it
                int sniType   = payload[pos + 2] & 0xFF;
                int sniLength = readUint16BE(payload, pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extLength - 5) break;

                String sni = new String(payload, pos + 5, sniLength);
                return Optional.of(sni);
            }

            pos += extLength;
        }

        return Optional.empty();
    }

    /** Read a 16-bit big-endian unsigned value. */
    static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
