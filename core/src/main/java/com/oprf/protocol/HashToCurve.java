package com.oprf.protocol;

import com.oprf.CipherSuite;
import com.oprf.core.GroupElement;
import com.oprf.core.Scalar;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Implements hash-to-curve for P-256 per RFC 9380.
 * Uses the "P256_XMD:SHA-256_SSWU_RO_" suite.
 */
public final class HashToCurve {

    private static final BigInteger FIELD_PRIME = CipherSuite.getFieldPrime();
    private static final BigInteger CURVE_A = CipherSuite.getCurveA();
    private static final BigInteger CURVE_B = CipherSuite.getCurveB();
    private static final BigInteger Z = CipherSuite.SWU_Z;
    private static final int L = CipherSuite.EXPAND_LENGTH; // 48 bytes for P-256

    // Precomputed constants for sqrt_ratio
    // c1 = (p - 3) / 4
    private static final BigInteger C1 = FIELD_PRIME.subtract(BigInteger.valueOf(3))
            .divide(BigInteger.valueOf(4));
    // c2 = sqrt(-Z) mod p
    private static final BigInteger C2 = computeSqrtNegZ();

    private HashToCurve() {
        // Utility class
    }

    /**
     * Compute sqrt(-Z) for P-256 where Z = -10.
     * So -Z = 10, and we need sqrt(10) mod p.
     */
    private static BigInteger computeSqrtNegZ() {
        BigInteger negZ = Z.negate().mod(FIELD_PRIME);
        // For p ≡ 3 (mod 4), sqrt(x) = x^((p+1)/4)
        BigInteger exp = FIELD_PRIME.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
        return negZ.modPow(exp, FIELD_PRIME);
    }

    /**
     * Hashes arbitrary bytes to a curve point using random oracle method.
     *
     * @param msg the message to hash
     * @param dst the domain separation tag
     * @return a point on P-256
     */
    public static GroupElement hashToCurve(byte[] msg, byte[] dst) {
        // hash_to_curve with count = 2 for random oracle
        BigInteger[] u = hashToField(msg, dst, 2, FIELD_PRIME);

        // Map each field element to a curve point
        ECPoint q0 = mapToCurve(u[0]);
        ECPoint q1 = mapToCurve(u[1]);

        // Add the points and clear cofactor (cofactor = 1 for P-256)
        ECPoint result = q0.add(q1).normalize();

        return GroupElement.of(result);
    }

    /**
     * Hashes arbitrary bytes to a scalar.
     *
     * @param msg the message to hash
     * @param dst the domain separation tag
     * @return a scalar modulo the group order
     */
    public static Scalar hashToScalar(byte[] msg, byte[] dst) {
        BigInteger[] u = hashToField(msg, dst, 1, CipherSuite.getOrder());
        return Scalar.of(u[0]);
    }

    /**
     * Hash to field elements per RFC 9380 Section 5.2.
     */
    private static BigInteger[] hashToField(byte[] msg, byte[] dst, int count, BigInteger modulus) {
        int lenInBytes = count * L;
        byte[] uniformBytes = expandMessageXmd(msg, dst, lenInBytes);

        BigInteger[] result = new BigInteger[count];
        for (int i = 0; i < count; i++) {
            byte[] segment = new byte[L];
            System.arraycopy(uniformBytes, i * L, segment, 0, L);
            result[i] = new BigInteger(1, segment).mod(modulus);
        }
        return result;
    }

    /**
     * expand_message_xmd per RFC 9380 Section 5.3.1.
     * Uses SHA-256 as the hash function.
     */
    private static byte[] expandMessageXmd(byte[] msg, byte[] dst, int lenInBytes) {
        int bInBytes = 32; // SHA-256 output length
        int sInBytes = 64; // SHA-256 block size

        if (lenInBytes > 255 * bInBytes) {
            throw new IllegalArgumentException("Requested length too large");
        }
        if (dst.length > 255) {
            throw new IllegalArgumentException("DST too long");
        }

        // DST_prime = DST || I2OSP(len(DST), 1)
        byte[] dstPrime = new byte[dst.length + 1];
        System.arraycopy(dst, 0, dstPrime, 0, dst.length);
        dstPrime[dst.length] = (byte) dst.length;

        // Z_pad = I2OSP(0, s_in_bytes)
        byte[] zPad = new byte[sInBytes];

        // l_i_b_str = I2OSP(len_in_bytes, 2)
        byte[] libStr = new byte[]{(byte) (lenInBytes >> 8), (byte) lenInBytes};

        // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        byte[] msgPrime = concat(zPad, msg, libStr, new byte[]{0}, dstPrime);

        // b_0 = H(msg_prime)
        byte[] b0 = sha256(msgPrime);

        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        byte[] b1 = sha256(concat(b0, new byte[]{1}, dstPrime));

        int ell = (lenInBytes + bInBytes - 1) / bInBytes;
        byte[] uniformBytes = new byte[lenInBytes];
        byte[] bi = b1;

        for (int i = 1; i <= ell; i++) {
            int remaining = Math.min(bInBytes, lenInBytes - (i - 1) * bInBytes);
            System.arraycopy(bi, 0, uniformBytes, (i - 1) * bInBytes, remaining);

            if (i < ell) {
                // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i+1, 1) || DST_prime)
                byte[] xored = xor(b0, bi);
                bi = sha256(concat(xored, new byte[]{(byte) (i + 1)}, dstPrime));
            }
        }

        return uniformBytes;
    }

    /**
     * Simplified SWU map for P-256 per RFC 9380 Appendix F.2.
     * Following the algorithm exactly as specified in the RFC.
     */
    private static ECPoint mapToCurve(BigInteger u) {
        // Step 1-2: tv1 = Z * u^2
        BigInteger tv1 = u.multiply(u).mod(FIELD_PRIME);
        tv1 = Z.multiply(tv1).mod(FIELD_PRIME);

        // Step 3-4: tv2 = tv1^2 + tv1
        BigInteger tv2 = tv1.multiply(tv1).mod(FIELD_PRIME);
        tv2 = tv2.add(tv1).mod(FIELD_PRIME);

        // Step 5-6: tv3 = B * (tv2 + 1)
        BigInteger tv3 = tv2.add(BigInteger.ONE).mod(FIELD_PRIME);
        tv3 = CURVE_B.multiply(tv3).mod(FIELD_PRIME);

        // Step 7-8: tv4 = A * CMOV(Z, -tv2, tv2 != 0)
        BigInteger tv4;
        if (tv2.equals(BigInteger.ZERO)) {
            tv4 = Z;
        } else {
            tv4 = tv2.negate().mod(FIELD_PRIME);
        }
        tv4 = CURVE_A.multiply(tv4).mod(FIELD_PRIME);

        // Step 9: tv2 = tv3^2
        tv2 = tv3.multiply(tv3).mod(FIELD_PRIME);

        // Step 10: tv6 = tv4^2
        BigInteger tv6 = tv4.multiply(tv4).mod(FIELD_PRIME);

        // Step 11-12: tv2 = tv2 + A * tv6
        BigInteger tv5 = CURVE_A.multiply(tv6).mod(FIELD_PRIME);
        tv2 = tv2.add(tv5).mod(FIELD_PRIME);

        // Step 13: tv2 = tv2 * tv3
        tv2 = tv2.multiply(tv3).mod(FIELD_PRIME);

        // Step 14: tv6 = tv6 * tv4
        tv6 = tv6.multiply(tv4).mod(FIELD_PRIME);

        // Step 15-16: tv2 = tv2 + B * tv6
        tv5 = CURVE_B.multiply(tv6).mod(FIELD_PRIME);
        tv2 = tv2.add(tv5).mod(FIELD_PRIME);

        // Step 17: x = tv1 * tv3
        BigInteger x = tv1.multiply(tv3).mod(FIELD_PRIME);

        // Step 18: (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
        SqrtRatioResult sqrtResult = sqrtRatio(tv2, tv6);
        boolean isGx1Square = sqrtResult.isQR;
        BigInteger y1 = sqrtResult.y;

        // Step 19-20: y = tv1 * u * y1
        BigInteger y = tv1.multiply(u).mod(FIELD_PRIME);
        y = y.multiply(y1).mod(FIELD_PRIME);

        // Step 21: x = CMOV(x, tv3, is_gx1_square)
        if (isGx1Square) {
            x = tv3;
        }

        // Step 22: y = CMOV(y, y1, is_gx1_square)
        if (isGx1Square) {
            y = y1;
        }

        // Step 23-24: Adjust sign of y
        boolean e1 = sgn0(u) == sgn0(y);
        if (!e1) {
            y = y.negate().mod(FIELD_PRIME);
        }

        // Step 25: x = x / tv4
        BigInteger xAffine = x.multiply(tv4.modInverse(FIELD_PRIME)).mod(FIELD_PRIME);

        return CipherSuite.getCurve().createPoint(xAffine, y);
    }

    /**
     * sqrt_ratio for p ≡ 3 (mod 4) per RFC 9380 Appendix F.2.1.
     * Returns (is_square, sqrt(u/v)) if u/v is square, else (false, sqrt(Z * u/v)).
     */
    private static SqrtRatioResult sqrtRatio(BigInteger u, BigInteger v) {
        // tv1 = v^2
        BigInteger tv1 = v.multiply(v).mod(FIELD_PRIME);
        // tv2 = u * v
        BigInteger tv2 = u.multiply(v).mod(FIELD_PRIME);
        // tv1 = tv1 * tv2  (now tv1 = u * v^3)
        tv1 = tv1.multiply(tv2).mod(FIELD_PRIME);
        // y1 = tv1^c1     (c1 = (p-3)/4)
        BigInteger y1 = tv1.modPow(C1, FIELD_PRIME);
        // y1 = y1 * tv2   (now y1 = (u * v)^((p+1)/4) = potential sqrt(u/v) * v)
        y1 = y1.multiply(tv2).mod(FIELD_PRIME);
        // y2 = y1 * c2    (c2 = sqrt(-Z))
        BigInteger y2 = y1.multiply(C2).mod(FIELD_PRIME);
        // tv3 = y1^2 * v
        BigInteger tv3 = y1.multiply(y1).mod(FIELD_PRIME);
        tv3 = tv3.multiply(v).mod(FIELD_PRIME);
        // isQR = (tv3 == u)
        boolean isQR = tv3.equals(u);
        // y = CMOV(y2, y1, isQR)
        BigInteger y = isQR ? y1 : y2;

        return new SqrtRatioResult(isQR, y);
    }

    private static class SqrtRatioResult {
        final boolean isQR;
        final BigInteger y;

        SqrtRatioResult(boolean isQR, BigInteger y) {
            this.isQR = isQR;
            this.y = y;
        }
    }

    /**
     * Sign of a field element: 0 if even, 1 if odd.
     */
    private static int sgn0(BigInteger x) {
        return x.testBit(0) ? 1 : 0;
    }

    private static byte[] sha256(byte[] input) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(input, 0, input.length);
        byte[] result = new byte[32];
        digest.doFinal(result, 0);
        return result;
    }

    private static byte[] concat(byte[]... arrays) {
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

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}
