package com.oprf.core;

import com.oprf.CipherSuite;
import com.oprf.exception.OprfException;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a scalar value (field element) modulo the group order.
 * Used for private keys and arithmetic operations.
 */
public final class Scalar {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final BigInteger ORDER = CipherSuite.getOrder();

    private final BigInteger value;

    private Scalar(BigInteger value) {
        // Ensure value is in valid range [0, n-1]
        this.value = value.mod(ORDER);
    }

    /**
     * Creates a scalar from a BigInteger value.
     *
     * @param value the scalar value
     * @return a new Scalar
     */
    public static Scalar of(BigInteger value) {
        Objects.requireNonNull(value, "Scalar value cannot be null");
        return new Scalar(value);
    }

    /**
     * Creates a scalar from a byte array (big-endian encoding).
     *
     * @param bytes the scalar bytes
     * @return a new Scalar
     */
    public static Scalar fromBytes(byte[] bytes) {
        Objects.requireNonNull(bytes, "Bytes cannot be null");
        if (bytes.length != CipherSuite.SCALAR_LENGTH) {
            throw OprfException.invalidScalar("Expected " + CipherSuite.SCALAR_LENGTH +
                    " bytes, got " + bytes.length);
        }
        BigInteger value = new BigInteger(1, bytes);
        if (value.compareTo(ORDER) >= 0) {
            throw OprfException.invalidScalar("Scalar out of range");
        }
        return new Scalar(value);
    }

    /**
     * Generates a random non-zero scalar suitable for use as a private key.
     *
     * @return a random Scalar in range [1, n-1]
     */
    public static Scalar random() {
        byte[] bytes = new byte[CipherSuite.SCALAR_LENGTH];
        BigInteger value;
        do {
            SECURE_RANDOM.nextBytes(bytes);
            value = new BigInteger(1, bytes);
        } while (value.equals(BigInteger.ZERO) || value.compareTo(ORDER) >= 0);
        return new Scalar(value);
    }

    /**
     * Returns the zero scalar.
     */
    public static Scalar zero() {
        return new Scalar(BigInteger.ZERO);
    }

    /**
     * Returns the one scalar.
     */
    public static Scalar one() {
        return new Scalar(BigInteger.ONE);
    }

    /**
     * Returns the underlying BigInteger value.
     */
    public BigInteger getValue() {
        return value;
    }

    /**
     * Checks if this scalar is zero.
     */
    public boolean isZero() {
        return value.equals(BigInteger.ZERO);
    }

    /**
     * Adds another scalar to this one (mod n).
     *
     * @param other the scalar to add
     * @return the sum
     */
    public Scalar add(Scalar other) {
        return new Scalar(value.add(other.value).mod(ORDER));
    }

    /**
     * Subtracts another scalar from this one (mod n).
     *
     * @param other the scalar to subtract
     * @return the difference
     */
    public Scalar subtract(Scalar other) {
        return new Scalar(value.subtract(other.value).mod(ORDER));
    }

    /**
     * Multiplies this scalar by another (mod n).
     *
     * @param other the scalar to multiply
     * @return the product
     */
    public Scalar multiply(Scalar other) {
        return new Scalar(value.multiply(other.value).mod(ORDER));
    }

    /**
     * Computes the modular inverse of this scalar (mod n).
     *
     * @return the multiplicative inverse
     * @throws OprfException if this scalar is zero
     */
    public Scalar invert() {
        if (isZero()) {
            throw OprfException.invalidScalar("Cannot invert zero");
        }
        return new Scalar(value.modInverse(ORDER));
    }

    /**
     * Negates this scalar (mod n).
     *
     * @return the negation
     */
    public Scalar negate() {
        return new Scalar(ORDER.subtract(value));
    }

    /**
     * Serializes this scalar to a fixed-length byte array (big-endian).
     *
     * @return 32-byte representation
     */
    public byte[] toBytes() {
        byte[] result = new byte[CipherSuite.SCALAR_LENGTH];
        byte[] valueBytes = value.toByteArray();

        // Handle sign byte and padding
        int srcPos = valueBytes[0] == 0 ? 1 : 0;
        int srcLen = valueBytes.length - srcPos;
        int destPos = CipherSuite.SCALAR_LENGTH - srcLen;

        if (destPos >= 0 && srcLen <= CipherSuite.SCALAR_LENGTH) {
            System.arraycopy(valueBytes, srcPos, result, destPos, srcLen);
        } else {
            throw OprfException.serializationError("Scalar value too large");
        }

        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Scalar scalar)) return false;
        // Constant-time comparison
        byte[] thisBytes = this.toBytes();
        byte[] otherBytes = scalar.toBytes();
        int diff = 0;
        for (int i = 0; i < CipherSuite.SCALAR_LENGTH; i++) {
            diff |= thisBytes[i] ^ otherBytes[i];
        }
        return diff == 0;
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return "Scalar[...]"; // Don't expose value in logs
    }
}
