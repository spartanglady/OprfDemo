package com.oprf;

import com.oprf.OprfServer.ServerResponse;
import com.oprf.core.GroupElement;
import com.oprf.core.Scalar;
import com.oprf.exception.OprfException;
import com.oprf.protocol.HashToCurve;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for OprfServer.
 */
class OprfServerTest {

    @ParameterizedTest
    @EnumSource(OprfMode.class)
    void testServerCreation(OprfMode mode) {
        OprfServer server = OprfServer.create(mode);

        assertNotNull(server);
        assertEquals(mode, server.getMode());
        assertNotNull(server.getPublicKey());
        assertEquals(CipherSuite.ELEMENT_LENGTH, server.getPublicKey().length);
    }

    @ParameterizedTest
    @EnumSource(OprfMode.class)
    void testServerFromPrivateKey(OprfMode mode) {
        OprfServer server1 = OprfServer.create(mode);
        byte[] privateKey = server1.exportPrivateKey();

        OprfServer server2 = OprfServer.create(mode, privateKey);

        assertArrayEquals(server1.getPublicKey(), server2.getPublicKey());
        assertArrayEquals(server1.exportPrivateKey(), server2.exportPrivateKey());
    }

    @Test
    void testBaseOprfEvaluation() {
        OprfServer server = OprfServer.create(OprfMode.BASE);

        // Create a blinded element (simulating client)
        byte[] input = "test input".getBytes();
        GroupElement blindedElement = HashToCurve.hashToCurve(
                input, CipherSuite.getHashToCurveDST(OprfMode.BASE));

        ServerResponse response = server.evaluate(blindedElement.toBytes());

        assertNotNull(response.getEvaluatedElement());
        assertEquals(CipherSuite.ELEMENT_LENGTH, response.getEvaluatedElement().length);
        assertFalse(response.hasProof());
        assertNull(response.getProof());
    }

    @Test
    void testVoprfEvaluationWithProof() {
        OprfServer server = OprfServer.create(OprfMode.VERIFIABLE);

        byte[] input = "test input".getBytes();
        GroupElement blindedElement = HashToCurve.hashToCurve(
                input, CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE));

        ServerResponse response = server.evaluate(blindedElement.toBytes());

        assertNotNull(response.getEvaluatedElement());
        assertTrue(response.hasProof());
        assertNotNull(response.getProof());
        assertEquals(64, response.getProof().length); // c || s, 32 bytes each
    }

    @Test
    void testPoprfEvaluationWithInfo() {
        OprfServer server = OprfServer.create(OprfMode.PARTIAL);

        byte[] input = "test input".getBytes();
        byte[] info = "public metadata".getBytes();
        GroupElement blindedElement = HashToCurve.hashToCurve(
                input, CipherSuite.getHashToCurveDST(OprfMode.PARTIAL));

        ServerResponse response = server.evaluate(blindedElement.toBytes(), info);

        assertNotNull(response.getEvaluatedElement());
        assertTrue(response.hasProof());
        assertNotNull(response.getProof());
    }

    @Test
    void testPoprfDifferentInfoGivesDifferentResults() {
        OprfServer server = OprfServer.create(OprfMode.PARTIAL);

        byte[] input = "test input".getBytes();
        GroupElement blindedElement = HashToCurve.hashToCurve(
                input, CipherSuite.getHashToCurveDST(OprfMode.PARTIAL));

        ServerResponse response1 = server.evaluate(blindedElement.toBytes(), "info1".getBytes());
        ServerResponse response2 = server.evaluate(blindedElement.toBytes(), "info2".getBytes());

        assertFalse(Arrays.equals(response1.getEvaluatedElement(), response2.getEvaluatedElement()));
    }

    @Test
    void testInfoNotSupportedInBaseMode() {
        OprfServer server = OprfServer.create(OprfMode.BASE);
        byte[] blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.BASE)).toBytes();

        assertThrows(IllegalStateException.class, () ->
                server.evaluate(blindedElement, "info".getBytes()));
    }

    @Test
    void testInfoRequiredInPartialMode() {
        OprfServer server = OprfServer.create(OprfMode.PARTIAL);
        byte[] blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.PARTIAL)).toBytes();

        assertThrows(IllegalStateException.class, () -> server.evaluate(blindedElement));
        assertThrows(IllegalStateException.class, () -> server.evaluateBatch(List.of(blindedElement)));
    }

    @Test
    void testBatchEvaluation() {
        OprfServer server = OprfServer.create(OprfMode.VERIFIABLE);

        List<byte[]> blindedElements = List.of(
                HashToCurve.hashToCurve("input1".getBytes(),
                        CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE)).toBytes(),
                HashToCurve.hashToCurve("input2".getBytes(),
                        CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE)).toBytes(),
                HashToCurve.hashToCurve("input3".getBytes(),
                        CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE)).toBytes()
        );

        List<ServerResponse> responses = server.evaluateBatch(blindedElements);

        assertEquals(3, responses.size());
        for (ServerResponse response : responses) {
            assertNotNull(response.getEvaluatedElement());
            assertTrue(response.hasProof());
        }
    }

    @Test
    void testDeterministicEvaluation() {
        OprfServer server = OprfServer.create(OprfMode.BASE);

        byte[] blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.BASE)).toBytes();

        ServerResponse response1 = server.evaluate(blindedElement);
        ServerResponse response2 = server.evaluate(blindedElement);

        // Same input should give same evaluated element
        assertArrayEquals(response1.getEvaluatedElement(), response2.getEvaluatedElement());
    }

    @Test
    void testInvalidBlindedElement() {
        OprfServer server = OprfServer.create(OprfMode.BASE);

        // Create an invalid point - using 0x04 (uncompressed) prefix with wrong length
        // will cause a decoding error
        byte[] invalidElement = new byte[33];
        invalidElement[0] = 0x04; // Uncompressed prefix but wrong length (should be 65 bytes)
        for (int i = 1; i < 33; i++) {
            invalidElement[i] = (byte) 0xFF;
        }

        assertThrows(OprfException.class, () -> server.evaluate(invalidElement));
    }

    @Test
    void testWrongSizeInput() {
        OprfServer server = OprfServer.create(OprfMode.BASE);

        assertThrows(OprfException.class, () -> server.evaluate(new byte[32]));
        assertThrows(OprfException.class, () -> server.evaluate(new byte[34]));
    }

    @Test
    void testNullInputs() {
        OprfServer server = OprfServer.create(OprfMode.BASE);

        assertThrows(NullPointerException.class, () -> server.evaluate((byte[]) null));
        assertThrows(NullPointerException.class, () -> OprfServer.create(null));
        assertThrows(NullPointerException.class, () -> OprfServer.create(OprfMode.BASE, null));
    }

    @Test
    void testEmptyBatch() {
        OprfServer server = OprfServer.create(OprfMode.BASE);

        assertThrows(IllegalArgumentException.class, () -> server.evaluateBatch(List.of()));
    }
}
