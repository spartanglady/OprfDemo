package com.oprf.protocol;

import com.oprf.CipherSuite;
import com.oprf.OprfMode;
import com.oprf.core.GroupElement;
import com.oprf.core.Scalar;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for hash-to-curve implementation.
 */
class HashToCurveTest {

    @Test
    void testHashToCurveProducesValidPoint() {
        byte[] msg = "test message".getBytes();
        byte[] dst = CipherSuite.getHashToCurveDST(OprfMode.BASE);

        GroupElement point = HashToCurve.hashToCurve(msg, dst);

        assertNotNull(point);
        assertFalse(point.isIdentity());
        // Point should serialize to valid compressed format
        assertEquals(33, point.toBytes().length);
        // First byte should be 0x02 or 0x03 (compressed point prefix)
        byte prefix = point.toBytes()[0];
        assertTrue(prefix == 0x02 || prefix == 0x03);
    }

    @Test
    void testHashToCurveIsDeterministic() {
        byte[] msg = "test message".getBytes();
        byte[] dst = CipherSuite.getHashToCurveDST(OprfMode.BASE);

        GroupElement point1 = HashToCurve.hashToCurve(msg, dst);
        GroupElement point2 = HashToCurve.hashToCurve(msg, dst);

        assertEquals(point1, point2);
        assertArrayEquals(point1.toBytes(), point2.toBytes());
    }

    @Test
    void testDifferentMessagesProduceDifferentPoints() {
        byte[] dst = CipherSuite.getHashToCurveDST(OprfMode.BASE);

        GroupElement point1 = HashToCurve.hashToCurve("message1".getBytes(), dst);
        GroupElement point2 = HashToCurve.hashToCurve("message2".getBytes(), dst);

        assertNotEquals(point1, point2);
    }

    @Test
    void testDifferentDSTsProduceDifferentPoints() {
        byte[] msg = "test message".getBytes();

        GroupElement point1 = HashToCurve.hashToCurve(msg, "DST1".getBytes());
        GroupElement point2 = HashToCurve.hashToCurve(msg, "DST2".getBytes());

        assertNotEquals(point1, point2);
    }

    @Test
    void testHashToScalar() {
        byte[] msg = "test message".getBytes();
        byte[] dst = CipherSuite.getHashToScalarDST(OprfMode.BASE);

        Scalar scalar = HashToCurve.hashToScalar(msg, dst);

        assertNotNull(scalar);
        assertFalse(scalar.isZero());
        // Scalar should be in valid range
        assertTrue(scalar.getValue().compareTo(CipherSuite.getOrder()) < 0);
    }

    @Test
    void testHashToScalarIsDeterministic() {
        byte[] msg = "test message".getBytes();
        byte[] dst = CipherSuite.getHashToScalarDST(OprfMode.BASE);

        Scalar scalar1 = HashToCurve.hashToScalar(msg, dst);
        Scalar scalar2 = HashToCurve.hashToScalar(msg, dst);

        assertEquals(scalar1, scalar2);
    }

    @Test
    void testEmptyMessage() {
        byte[] msg = new byte[0];
        byte[] dst = "DST".getBytes();

        GroupElement point = HashToCurve.hashToCurve(msg, dst);
        assertNotNull(point);
        assertFalse(point.isIdentity());
    }

    @Test
    void testLargeMessage() {
        byte[] msg = new byte[10000];
        for (int i = 0; i < msg.length; i++) {
            msg[i] = (byte) i;
        }
        byte[] dst = "DST".getBytes();

        GroupElement point = HashToCurve.hashToCurve(msg, dst);
        assertNotNull(point);
        assertFalse(point.isIdentity());
    }
}
