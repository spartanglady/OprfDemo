package com.oprf.util;

import com.oprf.CipherSuite;
import com.oprf.OprfMode;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Builds context strings for OPRF protocol as defined in RFC 9497.
 *
 * Context string format:
 * "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
 */
public final class ContextString {

    private static final byte[] PROTOCOL_ID = "OPRFV1-".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DASH = "-".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_SEED = "Seed-".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_DERIVE_KEY = "DeriveKeyPair".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_COMPOSITE = "Composite".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_CHALLENGE = "Challenge".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_FINALIZE = "Finalize".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_INFO = "Info".getBytes(StandardCharsets.US_ASCII);

    private ContextString() {
        // Utility class
    }

    /**
     * Creates the full context string for the given mode.
     *
     * @param mode the OPRF mode
     * @return the context string as bytes
     */
    public static byte[] create(OprfMode mode) {
        Objects.requireNonNull(mode, "Mode cannot be null");
        return concat(
                PROTOCOL_ID,
                new byte[]{mode.getIdentifier()},
                DASH,
                CipherSuite.SUITE_NAME.getBytes(StandardCharsets.US_ASCII)
        );
    }

    /**
     * Creates the seed DST for DeriveKeyPair.
     */
    public static byte[] seedDst(OprfMode mode) {
        return concat(LABEL_SEED, create(mode));
    }

    /**
     * Creates the key derivation DST.
     */
    public static byte[] deriveKeyDst(OprfMode mode) {
        return concat(LABEL_DERIVE_KEY, create(mode));
    }

    /**
     * Returns the "Composite" label used in DLEQ transcripts.
     */
    public static byte[] compositeDst(OprfMode mode) {
        return LABEL_COMPOSITE;
    }

    /**
     * Returns the "Challenge" label used in DLEQ transcripts.
     */
    public static byte[] challengeDst(OprfMode mode) {
        return LABEL_CHALLENGE;
    }

    /**
     * Returns the "Finalize" label used in output derivation.
     */
    public static byte[] finalizeDst(OprfMode mode) {
        return LABEL_FINALIZE;
    }

    /**
     * Returns the "Info" label used in POPRF info framing.
     */
    public static byte[] infoDst(OprfMode mode) {
        return LABEL_INFO;
    }

    /**
     * Encodes a length-prefixed byte array (I2OSP(len, 2) || data).
     */
    public static byte[] lengthPrefixed(byte[] data) {
        if (data.length > 0xFFFF) {
            throw new IllegalArgumentException("Data length exceeds 65535 bytes");
        }
        ByteBuffer buffer = ByteBuffer.allocate(2 + data.length);
        buffer.putShort((short) data.length);
        buffer.put(data);
        return buffer.array();
    }

    /**
     * Concatenates multiple byte arrays.
     */
    public static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) {
            totalLength += arr.length;
        }
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }
}
