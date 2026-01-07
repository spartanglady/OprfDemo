package com.oprf.protocol;

import com.oprf.CipherSuite;
import com.oprf.OprfMode;
import com.oprf.core.GroupElement;
import com.oprf.core.Proof;
import com.oprf.core.Scalar;
import com.oprf.util.ContextString;
import com.oprf.util.Serialization;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Implements DLEQ (Discrete Log Equality) proofs for VOPRF and POPRF modes.
 *
 * Proves that log_A(B) = log_C(D) without revealing the discrete log.
 * Used to prove the server used its private key correctly.
 */
public final class DleqProver {

    private final OprfMode mode;

    public DleqProver(OprfMode mode) {
        this.mode = mode;
    }

    /**
     * Generates a batch DLEQ proof for multiple evaluations.
     *
     * @param k      the private key scalar
     * @param A      the generator (G for OPRF/VOPRF)
     * @param B      the public key (pk = k * A)
     * @param Cs     the list of blinded inputs
     * @param Ds     the list of evaluated outputs (D_i = k * C_i)
     * @return the DLEQ proof
     */
    public Proof generateBatchProof(Scalar k, GroupElement A, GroupElement B,
                                    List<GroupElement> Cs, List<GroupElement> Ds) {
        return generateBatchProofInternal(k, A, B, Cs, Ds, Scalar.random());
    }

    Proof generateBatchProofWithNonce(Scalar k, GroupElement A, GroupElement B,
                                      List<GroupElement> Cs, List<GroupElement> Ds,
                                      Scalar nonce) {
        if (nonce == null) {
            throw new IllegalArgumentException("Nonce cannot be null");
        }
        return generateBatchProofInternal(k, A, B, Cs, Ds, nonce);
    }

    /**
     * Generates a DLEQ proof for a single evaluation.
     *
     * @param k  the private key scalar
     * @param A  the generator
     * @param B  the public key (B = k * A)
     * @param C  the blinded input
     * @param D  the evaluated output (D = k * C)
     * @return the DLEQ proof
     */
    public Proof generateProof(Scalar k, GroupElement A, GroupElement B,
                               GroupElement C, GroupElement D) {
        return generateBatchProof(k, A, B, List.of(C), List.of(D));
    }

    /**
     * Verifies a batch DLEQ proof.
     *
     * @param A      the generator
     * @param B      the public key
     * @param Cs     the list of blinded inputs
     * @param Ds     the list of evaluated outputs
     * @param proof  the proof to verify
     * @return true if the proof is valid
     */
    public boolean verifyBatchProof(GroupElement A, GroupElement B,
                                    List<GroupElement> Cs, List<GroupElement> Ds,
                                    Proof proof) {
        if (proof == null || Cs.size() != Ds.size() || Cs.isEmpty()) {
            return false;
        }

        CompositeResult composite = computeComposites(B, Cs, Ds);
        return verifyProofInternal(A, B, composite.M, composite.Z, proof);
    }

    /**
     * Verifies a DLEQ proof for a single evaluation.
     */
    public boolean verifyProof(GroupElement A, GroupElement B,
                               GroupElement C, GroupElement D,
                               Proof proof) {
        return verifyBatchProof(A, B, List.of(C), List.of(D), proof);
    }

    private Proof generateBatchProofInternal(Scalar k, GroupElement A, GroupElement B,
                                             List<GroupElement> Cs, List<GroupElement> Ds,
                                             Scalar nonce) {
        validateBatchInputs(Cs, Ds);

        CompositeResult composite = computeCompositesFast(k, B, Cs, Ds);
        return generateProofInternal(k, A, B, composite.M, composite.Z, nonce);
    }

    private static void validateBatchInputs(List<GroupElement> Cs, List<GroupElement> Ds) {
        if (Cs.isEmpty()) {
            throw new IllegalArgumentException("Input lists must be non-empty");
        }
        if (Cs.size() != Ds.size()) {
            throw new IllegalArgumentException("Input and output lists must have same size");
        }
        if (Cs.size() > 0xFFFF) {
            throw new IllegalArgumentException("Batch size exceeds 65535 elements");
        }
    }

    /**
     * Computes composite elements for batch proof generation using the secret key.
     * Returns M and Z where the proof shows log_A(B) = log_M(Z).
     */
    private CompositeResult computeCompositesFast(Scalar k, GroupElement B,
                                                  List<GroupElement> Cs, List<GroupElement> Ds) {
        byte[] seed = computeSeed(B);
        GroupElement M = GroupElement.identity();

        for (int i = 0; i < Cs.size(); i++) {
            Scalar di = computeCompositeScalar(seed, i, Cs.get(i), Ds.get(i));
            M = M.add(Cs.get(i).multiply(di));
        }

        GroupElement Z = M.multiply(k);
        return new CompositeResult(M, Z);
    }

    /**
     * Computes composite elements for proof verification.
     */
    private CompositeResult computeComposites(GroupElement B,
                                              List<GroupElement> Cs, List<GroupElement> Ds) {
        byte[] seed = computeSeed(B);
        GroupElement M = GroupElement.identity();
        GroupElement Z = GroupElement.identity();

        for (int i = 0; i < Cs.size(); i++) {
            Scalar di = computeCompositeScalar(seed, i, Cs.get(i), Ds.get(i));
            M = M.add(Cs.get(i).multiply(di));
            Z = Z.add(Ds.get(i).multiply(di));
        }

        return new CompositeResult(M, Z);
    }

    private byte[] computeSeed(GroupElement B) {
        byte[] Bm = B.toBytes();
        byte[] seedDst = ContextString.seedDst(mode);
        byte[] seedTranscript = ContextString.concat(
                Serialization.i2osp2(Bm.length), Bm,
                Serialization.i2osp2(seedDst.length), seedDst
        );
        return hash(seedTranscript);
    }

    private Scalar computeCompositeScalar(byte[] seed, int index,
                                          GroupElement C, GroupElement D) {
        if (index > 0xFFFF) {
            throw new IllegalArgumentException("Index exceeds 65535");
        }
        byte[] Ci = C.toBytes();
        byte[] Di = D.toBytes();
        byte[] compositeTranscript = ContextString.concat(
                Serialization.i2osp2(seed.length), seed,
                Serialization.i2osp2(index),
                Serialization.i2osp2(Ci.length), Ci,
                Serialization.i2osp2(Di.length), Di,
                ContextString.compositeDst(mode)
        );
        return HashToCurve.hashToScalar(compositeTranscript, CipherSuite.getHashToScalarDST(mode));
    }

    /**
     * Internal proof generation using the RFC 9497 transcript.
     */
    private Proof generateProofInternal(Scalar k, GroupElement A, GroupElement B,
                                        GroupElement M, GroupElement Z, Scalar nonce) {
        GroupElement t2 = A.multiply(nonce);
        GroupElement t3 = M.multiply(nonce);

        Scalar c = computeChallenge(B, M, Z, t2, t3);
        Scalar s = nonce.subtract(c.multiply(k));

        return new Proof(c, s);
    }

    /**
     * Internal proof verification.
     */
    private boolean verifyProofInternal(GroupElement A, GroupElement B,
                                        GroupElement M, GroupElement Z,
                                        Proof proof) {
        Scalar c = proof.getChallenge();
        Scalar s = proof.getResponse();

        GroupElement t2 = A.multiply(s).add(B.multiply(c));
        GroupElement t3 = M.multiply(s).add(Z.multiply(c));

        Scalar expectedC = computeChallenge(B, M, Z, t2, t3);
        return c.equals(expectedC);
    }

    private Scalar computeChallenge(GroupElement B, GroupElement M, GroupElement Z,
                                    GroupElement t2, GroupElement t3) {
        byte[] Bm = B.toBytes();
        byte[] a0 = M.toBytes();
        byte[] a1 = Z.toBytes();
        byte[] a2 = t2.toBytes();
        byte[] a3 = t3.toBytes();

        byte[] challengeTranscript = ContextString.concat(
                Serialization.i2osp2(Bm.length), Bm,
                Serialization.i2osp2(a0.length), a0,
                Serialization.i2osp2(a1.length), a1,
                Serialization.i2osp2(a2.length), a2,
                Serialization.i2osp2(a3.length), a3,
                ContextString.challengeDst(mode)
        );

        return HashToCurve.hashToScalar(challengeTranscript, CipherSuite.getHashToScalarDST(mode));
    }

    private static byte[] hash(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static class CompositeResult {
        final GroupElement M;
        final GroupElement Z;

        CompositeResult(GroupElement M, GroupElement Z) {
            this.M = M;
            this.Z = Z;
        }
    }
}
