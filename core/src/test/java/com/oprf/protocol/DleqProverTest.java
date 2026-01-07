package com.oprf.protocol;

import com.oprf.OprfMode;
import com.oprf.core.GroupElement;
import com.oprf.core.Proof;
import com.oprf.core.Scalar;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for DLEQ proof generation and verification.
 */
class DleqProverTest {

    @ParameterizedTest
    @EnumSource(value = OprfMode.class, names = {"VERIFIABLE", "PARTIAL"})
    void testProofGenerationAndVerification(OprfMode mode) {
        DleqProver prover = new DleqProver(mode);

        // Generate a random secret key
        Scalar k = Scalar.random();

        // A = G (generator), B = k * G (public key)
        GroupElement A = GroupElement.generator();
        GroupElement B = A.multiply(k);

        // C = some random point (blinded input), D = k * C (evaluated output)
        GroupElement C = A.multiply(Scalar.random());
        GroupElement D = C.multiply(k);

        // Generate proof
        Proof proof = prover.generateProof(k, A, B, C, D);

        assertNotNull(proof);
        assertNotNull(proof.getChallenge());
        assertNotNull(proof.getResponse());

        // Verify proof
        assertTrue(prover.verifyProof(A, B, C, D, proof));
    }

    @Test
    void testProofFailsWithWrongKey() {
        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);

        Scalar k = Scalar.random();
        Scalar wrongK = Scalar.random();

        GroupElement A = GroupElement.generator();
        GroupElement B = A.multiply(k);

        GroupElement C = A.multiply(Scalar.random());
        GroupElement D = C.multiply(wrongK); // Wrong key!

        // Generate proof with correct key
        Proof proof = prover.generateProof(k, A, B, C, D);

        // Verification should fail because D != k * C
        assertFalse(prover.verifyProof(A, B, C, D, proof));
    }

    @Test
    void testProofSerialization() {
        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);

        Scalar k = Scalar.random();
        GroupElement A = GroupElement.generator();
        GroupElement B = A.multiply(k);
        GroupElement C = A.multiply(Scalar.random());
        GroupElement D = C.multiply(k);

        Proof proof = prover.generateProof(k, A, B, C, D);

        // Serialize and deserialize
        byte[] proofBytes = proof.toBytes();
        assertEquals(64, proofBytes.length);

        Proof deserializedProof = Proof.fromBytes(proofBytes);

        // Verify the deserialized proof works
        assertTrue(prover.verifyProof(A, B, C, D, deserializedProof));
    }

    @Test
    void testBatchProof() {
        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);

        Scalar k = Scalar.random();
        GroupElement A = GroupElement.generator();
        GroupElement B = A.multiply(k);

        // Create multiple input/output pairs
        List<GroupElement> Cs = List.of(
                A.multiply(Scalar.random()),
                A.multiply(Scalar.random()),
                A.multiply(Scalar.random())
        );

        List<GroupElement> Ds = List.of(
                Cs.get(0).multiply(k),
                Cs.get(1).multiply(k),
                Cs.get(2).multiply(k)
        );

        // Generate batch proof
        Proof proof = prover.generateBatchProof(k, A, B, Cs, Ds);

        assertNotNull(proof);

        // Verify batch proof
        assertTrue(prover.verifyBatchProof(A, B, Cs, Ds, proof));
    }

    @Test
    void testBatchProofFailsWithTamperedOutput() {
        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);

        Scalar k = Scalar.random();
        GroupElement A = GroupElement.generator();
        GroupElement B = A.multiply(k);

        List<GroupElement> Cs = List.of(
                A.multiply(Scalar.random()),
                A.multiply(Scalar.random())
        );

        List<GroupElement> Ds = List.of(
                Cs.get(0).multiply(k),
                Cs.get(1).multiply(k)
        );

        Proof proof = prover.generateBatchProof(k, A, B, Cs, Ds);

        // Tamper with one output
        List<GroupElement> tamperedDs = List.of(
                Ds.get(0),
                A.multiply(Scalar.random()) // Wrong!
        );

        assertFalse(prover.verifyBatchProof(A, B, Cs, tamperedDs, proof));
    }

    @Test
    void testProofNonMalleability() {
        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);

        Scalar k = Scalar.random();
        GroupElement A = GroupElement.generator();
        GroupElement B = A.multiply(k);
        GroupElement C = A.multiply(Scalar.random());
        GroupElement D = C.multiply(k);

        Proof proof = prover.generateProof(k, A, B, C, D);

        // Modify the challenge slightly
        Scalar modifiedC = proof.getChallenge().add(Scalar.one());
        Proof tamperedProof = new Proof(modifiedC, proof.getResponse());

        assertFalse(prover.verifyProof(A, B, C, D, tamperedProof));
    }
}
