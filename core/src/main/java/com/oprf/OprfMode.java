package com.oprf;

/**
 * OPRF protocol modes as defined in RFC 9497.
 */
public enum OprfMode {
    /**
     * Base OPRF mode (modeOPRF).
     * Client learns F(k, x), server learns nothing about x.
     */
    BASE((byte) 0x00),

    /**
     * Verifiable OPRF mode (modeVOPRF).
     * Like BASE, but server provides a proof that it used the correct key.
     */
    VERIFIABLE((byte) 0x01),

    /**
     * Partially-Oblivious PRF mode (modePOPRF).
     * Allows public metadata input: F(k, x, info).
     */
    PARTIAL((byte) 0x02);

    private final byte identifier;

    OprfMode(byte identifier) {
        this.identifier = identifier;
    }

    /**
     * Returns the mode identifier byte as defined in RFC 9497.
     */
    public byte getIdentifier() {
        return identifier;
    }

    /**
     * Returns whether this mode includes a verifiable proof.
     */
    public boolean isVerifiable() {
        return this == VERIFIABLE || this == PARTIAL;
    }
}
