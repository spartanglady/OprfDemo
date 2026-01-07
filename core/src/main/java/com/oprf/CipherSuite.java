package com.oprf;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import com.oprf.util.ContextString;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * OPRF cipher suite configuration for P-256 with SHA-256 (suite identifier 0x0003).
 * Implements the parameters defined in RFC 9497 Section 4.
 */
public final class CipherSuite {

    /**
     * Suite identifier for P256-SHA256 as defined in RFC 9497.
     */
    public static final int SUITE_ID = 0x0003;

    /**
     * Name identifier for this suite.
     */
    public static final String SUITE_NAME = "P256-SHA256";

    /**
     * Hash output length in bytes (SHA-256 = 32 bytes).
     */
    public static final int HASH_LENGTH = 32;

    /**
     * Scalar (field element) length in bytes for P-256.
     */
    public static final int SCALAR_LENGTH = 32;

    /**
     * Compressed point length in bytes for P-256 (1 byte prefix + 32 bytes x-coordinate).
     */
    public static final int ELEMENT_LENGTH = 33;

    /**
     * Expand message length for hash-to-curve (L = ceil((ceil(log2(p)) + k) / 8) where k=128).
     */
    public static final int EXPAND_LENGTH = 48;

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256r1");
    private static final ECCurve CURVE = CURVE_PARAMS.getCurve();
    private static final ECPoint GENERATOR = CURVE_PARAMS.getG();
    private static final BigInteger ORDER = CURVE_PARAMS.getN();
    private static final BigInteger COFACTOR = CURVE_PARAMS.getH();
    private static final BigInteger FIELD_PRIME = CURVE.getField().getCharacteristic();

    // P-256 curve constants for simplified SWU
    private static final BigInteger CURVE_A = CURVE.getA().toBigInteger();
    private static final BigInteger CURVE_B = CURVE.getB().toBigInteger();

    // Z value for P-256 simplified SWU (Z = -10)
    public static final BigInteger SWU_Z = BigInteger.valueOf(-10).mod(FIELD_PRIME);

    private CipherSuite() {
        // Utility class
    }

    /**
     * Returns the elliptic curve used by this suite (P-256/secp256r1).
     */
    public static ECCurve getCurve() {
        return CURVE;
    }

    /**
     * Returns the generator point G for P-256.
     */
    public static ECPoint getGenerator() {
        return GENERATOR;
    }

    /**
     * Returns the group order n for P-256.
     */
    public static BigInteger getOrder() {
        return ORDER;
    }

    /**
     * Returns the cofactor h for P-256 (h = 1).
     */
    public static BigInteger getCofactor() {
        return COFACTOR;
    }

    /**
     * Returns the field prime p for P-256.
     */
    public static BigInteger getFieldPrime() {
        return FIELD_PRIME;
    }

    /**
     * Returns curve parameter a for P-256.
     */
    public static BigInteger getCurveA() {
        return CURVE_A;
    }

    /**
     * Returns curve parameter b for P-256.
     */
    public static BigInteger getCurveB() {
        return CURVE_B;
    }

    /**
     * Returns the RFC 9497 context string for this suite.
     * Format: "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
     * This value may contain non-printable characters; prefer {@link #getContextString(OprfMode)}.
     */
    @Deprecated
    public static String getContextStringPrefix(OprfMode mode) {
        return new String(ContextString.create(mode), StandardCharsets.US_ASCII);
    }

    /**
     * Returns the context string as raw bytes per RFC 9497.
     */
    public static byte[] getContextString(OprfMode mode) {
        return ContextString.create(mode);
    }

    /**
     * Returns the Domain Separation Tag (DST) for hash-to-curve operations.
     */
    public static byte[] getHashToCurveDST(OprfMode mode) {
        return ContextString.concat(
                "HashToGroup-".getBytes(StandardCharsets.US_ASCII),
                ContextString.create(mode)
        );
    }

    /**
     * Returns the DST for hash-to-scalar operations.
     */
    public static byte[] getHashToScalarDST(OprfMode mode) {
        return ContextString.concat(
                "HashToScalar-".getBytes(StandardCharsets.US_ASCII),
                ContextString.create(mode)
        );
    }
}
