package com.oprf.protocol;

import com.oprf.CipherSuite;
import com.oprf.OprfMode;
import com.oprf.core.GroupElement;
import com.oprf.core.KeyPair;
import com.oprf.protocol.BlindEvaluate.EvaluationResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for BlindEvaluate protocol implementation.
 */
class BlindEvaluateTest {

    @ParameterizedTest
    @EnumSource(OprfMode.class)
    void testEvaluation(OprfMode mode) {
        KeyPair keyPair = KeyPair.generate();
        BlindEvaluate evaluator = new BlindEvaluate(mode, keyPair);

        // Create a blinded element
        GroupElement blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(mode));

        EvaluationResult result = mode == OprfMode.PARTIAL
                ? evaluator.evaluate(blindedElement, "info".getBytes())
                : evaluator.evaluate(blindedElement);

        assertNotNull(result.getEvaluatedElement());
        assertFalse(result.getEvaluatedElement().isIdentity());

        if (mode.isVerifiable()) {
            assertNotNull(result.getProof());
        } else {
            assertNull(result.getProof());
        }
    }

    @Test
    void testPoprfWithInfo() {
        KeyPair keyPair = KeyPair.generate();
        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.PARTIAL, keyPair);

        GroupElement blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.PARTIAL));

        byte[] info = "metadata".getBytes();
        EvaluationResult result = evaluator.evaluate(blindedElement, info);

        assertNotNull(result.getEvaluatedElement());
        assertNotNull(result.getProof());
        // Public key should be tweaked
        assertFalse(java.util.Arrays.equals(
                result.getPublicKey().toBytes(),
                keyPair.exportPublicKey()));
    }

    @Test
    void testPoprfRequiresInfo() {
        KeyPair keyPair = KeyPair.generate();
        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.PARTIAL, keyPair);

        GroupElement blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.PARTIAL));

        assertThrows(IllegalArgumentException.class, () ->
                evaluator.evaluateBatch(List.of(blindedElement), null));
    }

    @Test
    void testInfoRejectedInNonPartialMode() {
        KeyPair keyPair = KeyPair.generate();
        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.BASE, keyPair);

        GroupElement blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.BASE));

        assertThrows(IllegalStateException.class, () ->
                evaluator.evaluateBatch(List.of(blindedElement), "info".getBytes()));
    }

    @Test
    void testPoprfDifferentInfoProducesDifferentResults() {
        KeyPair keyPair = KeyPair.generate();
        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.PARTIAL, keyPair);

        GroupElement blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.PARTIAL));

        EvaluationResult result1 = evaluator.evaluate(blindedElement, "info1".getBytes());
        EvaluationResult result2 = evaluator.evaluate(blindedElement, "info2".getBytes());

        assertNotEquals(result1.getEvaluatedElement(), result2.getEvaluatedElement());
    }

    @Test
    void testBatchEvaluation() {
        KeyPair keyPair = KeyPair.generate();
        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.VERIFIABLE, keyPair);

        List<GroupElement> blindedElements = List.of(
                HashToCurve.hashToCurve("test1".getBytes(),
                        CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE)),
                HashToCurve.hashToCurve("test2".getBytes(),
                        CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE)),
                HashToCurve.hashToCurve("test3".getBytes(),
                        CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE))
        );

        List<EvaluationResult> results = evaluator.evaluateBatch(blindedElements);

        assertEquals(3, results.size());
        for (EvaluationResult result : results) {
            assertNotNull(result.getEvaluatedElement());
            assertNotNull(result.getProof());
        }

        // All results should share the same proof in batch mode
        assertEquals(results.get(0).getProof(), results.get(1).getProof());
        assertEquals(results.get(1).getProof(), results.get(2).getProof());
    }

    @Test
    void testEvaluationIsConsistent() {
        KeyPair keyPair = KeyPair.generate();
        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.BASE, keyPair);

        GroupElement blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.BASE));

        EvaluationResult result1 = evaluator.evaluate(blindedElement);
        EvaluationResult result2 = evaluator.evaluate(blindedElement);

        // Same input should produce same output
        assertEquals(result1.getEvaluatedElement(), result2.getEvaluatedElement());
    }

    @Test
    void testDifferentKeysProduceDifferentResults() {
        KeyPair keyPair1 = KeyPair.generate();
        KeyPair keyPair2 = KeyPair.generate();

        BlindEvaluate evaluator1 = new BlindEvaluate(OprfMode.BASE, keyPair1);
        BlindEvaluate evaluator2 = new BlindEvaluate(OprfMode.BASE, keyPair2);

        GroupElement blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.BASE));

        EvaluationResult result1 = evaluator1.evaluate(blindedElement);
        EvaluationResult result2 = evaluator2.evaluate(blindedElement);

        assertNotEquals(result1.getEvaluatedElement(), result2.getEvaluatedElement());
    }

    @Test
    void testVoprfProofVerifies() {
        KeyPair keyPair = KeyPair.generate();
        BlindEvaluate evaluator = new BlindEvaluate(OprfMode.VERIFIABLE, keyPair);
        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);

        GroupElement blindedElement = HashToCurve.hashToCurve(
                "test".getBytes(), CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE));

        EvaluationResult result = evaluator.evaluate(blindedElement);

        // Verify the proof
        boolean valid = prover.verifyProof(
                GroupElement.generator(),
                keyPair.getPublicKey(),
                blindedElement,
                result.getEvaluatedElement(),
                result.getProof()
        );

        assertTrue(valid);
    }
}
