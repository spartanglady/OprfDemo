package com.oprf.core;

import com.oprf.CipherSuite;
import com.oprf.exception.OprfException;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertThrows;

class ScalarTest {

    @Test
    void testScalarFromBytesRejectsOutOfRange() {
        BigInteger order = CipherSuite.getOrder();
        byte[] orderBytes = order.toByteArray();
        byte[] candidate = new byte[CipherSuite.SCALAR_LENGTH];

        int srcPos = Math.max(0, orderBytes.length - CipherSuite.SCALAR_LENGTH);
        int length = Math.min(orderBytes.length, CipherSuite.SCALAR_LENGTH);
        System.arraycopy(orderBytes, srcPos, candidate, CipherSuite.SCALAR_LENGTH - length, length);

        assertThrows(OprfException.class, () -> Scalar.fromBytes(candidate));
    }
}
