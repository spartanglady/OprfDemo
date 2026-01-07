package com.oprf.core;

import com.oprf.CipherSuite;
import com.oprf.exception.OprfException;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents an element of the elliptic curve group (a point on P-256).
 * Provides operations for point arithmetic and serialization.
 */
public final class GroupElement {

    private final ECPoint point;

    private GroupElement(ECPoint point) {
        this.point = point.normalize();
    }

    /**
     * Creates a GroupElement from a Bouncy Castle ECPoint.
     *
     * @param point the EC point
     * @return a new GroupElement
     * @throws OprfException if the point is invalid
     */
    public static GroupElement of(ECPoint point) {
        Objects.requireNonNull(point, "Point cannot be null");
        validatePoint(point);
        return new GroupElement(point);
    }

    /**
     * Deserializes a GroupElement from its SEC1 compressed encoding.
     *
     * @param bytes the compressed point bytes
     * @return a new GroupElement
     * @throws OprfException if deserialization fails or point is invalid
     */
    public static GroupElement fromBytes(byte[] bytes) {
        Objects.requireNonNull(bytes, "Bytes cannot be null");
        if (bytes.length != CipherSuite.ELEMENT_LENGTH) {
            throw OprfException.invalidPoint("Expected " + CipherSuite.ELEMENT_LENGTH +
                    " bytes, got " + bytes.length);
        }

        try {
            ECPoint point = CipherSuite.getCurve().decodePoint(bytes);
            validatePoint(point);
            return new GroupElement(point);
        } catch (IllegalArgumentException e) {
            throw OprfException.invalidPoint("Failed to decode point: " + e.getMessage());
        }
    }

    /**
     * Returns the generator point G for the curve.
     */
    public static GroupElement generator() {
        return new GroupElement(CipherSuite.getGenerator());
    }

    /**
     * Returns the identity element (point at infinity).
     */
    public static GroupElement identity() {
        return new GroupElement(CipherSuite.getCurve().getInfinity());
    }

    /**
     * Validates that a point is valid for OPRF operations.
     */
    private static void validatePoint(ECPoint point) {
        if (point.isInfinity()) {
            throw OprfException.invalidPoint("Point at infinity not allowed");
        }
        if (!point.isValid()) {
            throw OprfException.invalidPoint("Point not on curve");
        }
    }

    /**
     * Returns the underlying ECPoint.
     */
    public ECPoint getPoint() {
        return point;
    }

    /**
     * Checks if this is the identity element (point at infinity).
     */
    public boolean isIdentity() {
        return point.isInfinity();
    }

    /**
     * Adds another group element to this one.
     *
     * @param other the element to add
     * @return the sum
     */
    public GroupElement add(GroupElement other) {
        return new GroupElement(point.add(other.point));
    }

    /**
     * Subtracts another group element from this one.
     *
     * @param other the element to subtract
     * @return the difference
     */
    public GroupElement subtract(GroupElement other) {
        return new GroupElement(point.subtract(other.point));
    }

    /**
     * Multiplies this element by a scalar.
     *
     * @param scalar the scalar multiplier
     * @return the scalar multiple
     */
    public GroupElement multiply(Scalar scalar) {
        ECPoint result = point.multiply(scalar.getValue());
        return new GroupElement(result);
    }

    /**
     * Negates this group element.
     *
     * @return the negation
     */
    public GroupElement negate() {
        return new GroupElement(point.negate());
    }

    /**
     * Serializes this element to SEC1 compressed format.
     *
     * @return 33-byte compressed encoding
     */
    public byte[] toBytes() {
        return point.getEncoded(true);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GroupElement that)) return false;
        return point.equals(that.point);
    }

    @Override
    public int hashCode() {
        return point.hashCode();
    }

    @Override
    public String toString() {
        byte[] encoded = toBytes();
        StringBuilder sb = new StringBuilder("GroupElement[");
        for (int i = 0; i < Math.min(4, encoded.length); i++) {
            sb.append(String.format("%02x", encoded[i]));
        }
        sb.append("...]");
        return sb.toString();
    }
}
