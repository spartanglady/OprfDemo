package com.oprf.core;

import com.oprf.CipherSuite;
import com.oprf.exception.OprfException;

import java.util.Objects;

/**
 * Represents a DLEQ (Discrete Log Equality) proof used in VOPRF and POPRF modes.
 * Proves that log_G(Y) = log_M(Z) without revealing the discrete log (the private key).
 *
 * The proof consists of two scalars (c, s) that satisfy:
 * - c = H(G, Y, M, Z, s*G + c*Y, s*M + c*Z)
 *
 * This proves knowledge of k such that Y = k*G and Z = k*M.
 */
public final class Proof {

    private final Scalar c;  // Challenge
    private final Scalar s;  // Response

    /**
     * Creates a new proof from challenge and response scalars.
     *
     * @param c the challenge scalar
     * @param s the response scalar
     */
    public Proof(Scalar c, Scalar s) {
        this.c = Objects.requireNonNull(c, "Challenge cannot be null");
        this.s = Objects.requireNonNull(s, "Response cannot be null");
    }

    /**
     * Deserializes a proof from bytes.
     * Format: c || s (32 bytes each, 64 bytes total)
     *
     * @param bytes the serialized proof
     * @return a new Proof
     */
    public static Proof fromBytes(byte[] bytes) {
        Objects.requireNonNull(bytes, "Bytes cannot be null");
        int expectedLength = 2 * CipherSuite.SCALAR_LENGTH;
        if (bytes.length != expectedLength) {
            throw OprfException.serializationError("Expected " + expectedLength +
                    " bytes for proof, got " + bytes.length);
        }

        byte[] cBytes = new byte[CipherSuite.SCALAR_LENGTH];
        byte[] sBytes = new byte[CipherSuite.SCALAR_LENGTH];
        System.arraycopy(bytes, 0, cBytes, 0, CipherSuite.SCALAR_LENGTH);
        System.arraycopy(bytes, CipherSuite.SCALAR_LENGTH, sBytes, 0, CipherSuite.SCALAR_LENGTH);

        return new Proof(Scalar.fromBytes(cBytes), Scalar.fromBytes(sBytes));
    }

    /**
     * Returns the challenge scalar.
     */
    public Scalar getChallenge() {
        return c;
    }

    /**
     * Returns the response scalar.
     */
    public Scalar getResponse() {
        return s;
    }

    /**
     * Serializes this proof to bytes.
     * Format: c || s (32 bytes each, 64 bytes total)
     *
     * @return 64-byte serialized proof
     */
    public byte[] toBytes() {
        byte[] result = new byte[2 * CipherSuite.SCALAR_LENGTH];
        byte[] cBytes = c.toBytes();
        byte[] sBytes = s.toBytes();
        System.arraycopy(cBytes, 0, result, 0, CipherSuite.SCALAR_LENGTH);
        System.arraycopy(sBytes, 0, result, CipherSuite.SCALAR_LENGTH, CipherSuite.SCALAR_LENGTH);
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Proof proof)) return false;
        return c.equals(proof.c) && s.equals(proof.s);
    }

    @Override
    public int hashCode() {
        return Objects.hash(c, s);
    }

    @Override
    public String toString() {
        return "Proof[c=..., s=...]";
    }
}
