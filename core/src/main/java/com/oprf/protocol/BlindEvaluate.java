package com.oprf.protocol;

import com.oprf.CipherSuite;
import com.oprf.OprfMode;
import com.oprf.core.GroupElement;
import com.oprf.core.KeyPair;
import com.oprf.core.Proof;
import com.oprf.core.Scalar;
import com.oprf.exception.OprfException;
import com.oprf.util.ContextString;
import com.oprf.util.Serialization;

import java.util.ArrayList;
import java.util.List;

/**
 * Implements the server-side BlindEvaluate operation for OPRF.
 *
 * This is the core server operation that evaluates blinded client inputs
 * without learning the actual inputs.
 */
public final class BlindEvaluate {

    private final OprfMode mode;
    private final KeyPair keyPair;
    private final DleqProver prover;

    public BlindEvaluate(OprfMode mode, KeyPair keyPair) {
        this.mode = mode;
        this.keyPair = keyPair;
        this.prover = mode.isVerifiable() ? new DleqProver(mode) : null;
    }

    /**
     * Evaluates a single blinded element.
     *
     * @param blindedElement the blinded input from the client
     * @return the evaluation result
     */
    public EvaluationResult evaluate(GroupElement blindedElement) {
        return evaluateBatch(List.of(blindedElement)).get(0);
    }

    /**
     * Evaluates a single blinded element with public info (POPRF mode).
     *
     * @param blindedElement the blinded input from the client
     * @param info           the public info parameter
     * @return the evaluation result
     */
    public EvaluationResult evaluate(GroupElement blindedElement, byte[] info) {
        return evaluateBatch(List.of(blindedElement), info).get(0);
    }

    /**
     * Evaluates multiple blinded elements in a batch.
     *
     * @param blindedElements the blinded inputs from the client
     * @return list of evaluation results
     */
    public List<EvaluationResult> evaluateBatch(List<GroupElement> blindedElements) {
        return evaluateBatch(blindedElements, null);
    }

    /**
     * Evaluates multiple blinded elements in a batch with public info (POPRF mode).
     *
     * @param blindedElements the blinded inputs from the client
     * @param info            the public info parameter (only for POPRF)
     * @return list of evaluation results
     */
    public List<EvaluationResult> evaluateBatch(List<GroupElement> blindedElements, byte[] info) {
        if (blindedElements.isEmpty()) {
            throw new IllegalArgumentException("Must provide at least one blinded element");
        }

        // Validate all input elements
        for (GroupElement element : blindedElements) {
            if (element.isIdentity()) {
                throw OprfException.invalidPoint("Blinded element cannot be identity");
            }
        }

        // Determine evaluation and proof parameters based on mode.
        Scalar evaluationScalar = keyPair.getPrivateKey();
        Scalar proofScalar = keyPair.getPrivateKey();
        GroupElement proofKey = keyPair.getPublicKey();
        boolean swapProofInputs = false;

        if (mode == OprfMode.PARTIAL) {
            if (info == null) {
                throw new IllegalArgumentException("Info parameter is required in PARTIAL (POPRF) mode");
            }
            validateInfoLength(info);
            TweakResult tweak = computeTweak(info);
            Scalar tweakedPrivateKey = tweak.tweakedPrivateKey;
            if (tweakedPrivateKey.isZero()) {
                throw OprfException.invalidScalar("Tweaked private key is zero");
            }
            evaluationScalar = tweakedPrivateKey.invert();
            proofScalar = tweakedPrivateKey;
            proofKey = tweak.tweakedPublicKey;
            swapProofInputs = true;
        } else if (info != null) {
            throw new IllegalStateException("Info parameter only supported in PARTIAL (POPRF) mode");
        }

        // Compute evaluated elements.
        List<GroupElement> evaluatedElements = new ArrayList<>(blindedElements.size());
        for (GroupElement blindedElement : blindedElements) {
            GroupElement evaluated = blindedElement.multiply(evaluationScalar);
            if (evaluated.isIdentity()) {
                throw OprfException.invalidPoint("Evaluated element is identity");
            }
            evaluatedElements.add(evaluated);
        }

        // Generate proof if in verifiable mode
        Proof proof = null;
        if (mode.isVerifiable()) {
            GroupElement A = GroupElement.generator();
            if (swapProofInputs) {
                proof = prover.generateBatchProof(proofScalar, A, proofKey, evaluatedElements, blindedElements);
            } else {
                proof = prover.generateBatchProof(proofScalar, A, proofKey, blindedElements, evaluatedElements);
            }
        }

        // Build results
        List<EvaluationResult> results = new ArrayList<>(blindedElements.size());
        for (int i = 0; i < evaluatedElements.size(); i++) {
            results.add(new EvaluationResult(
                    evaluatedElements.get(i),
                    proof,
                    proofKey
            ));
        }

        return results;
    }

    /**
     * Computes the POPRF key tweak from info.
     */
    private TweakResult computeTweak(byte[] info) {
        byte[] infoLabel = ContextString.infoDst(mode);
        byte[] framedInfo = ContextString.concat(
                infoLabel,
                Serialization.i2osp2(info.length),
                info
        );

        // Compute tweak scalar t = H(framedInfo)
        Scalar t = HashToCurve.hashToScalar(framedInfo, CipherSuite.getHashToScalarDST(mode));

        // tweakedKey = sk + t
        Scalar tweakedKey = keyPair.getPrivateKey().add(t);

        // tweakedPublicKey = pk + t * G
        GroupElement tG = GroupElement.generator().multiply(t);
        GroupElement tweakedPublicKey = keyPair.getPublicKey().add(tG);

        return new TweakResult(tweakedKey, tweakedPublicKey);
    }

    private static class TweakResult {
        final Scalar tweakedPrivateKey;
        final GroupElement tweakedPublicKey;

        TweakResult(Scalar tweakedPrivateKey, GroupElement tweakedPublicKey) {
            this.tweakedPrivateKey = tweakedPrivateKey;
            this.tweakedPublicKey = tweakedPublicKey;
        }
    }

    private static void validateInfoLength(byte[] info) {
        if (info.length > 0xFFFF) {
            throw new IllegalArgumentException("Info length exceeds 65535 bytes");
        }
    }

    /**
     * Result of a blind evaluation operation.
     */
    public static final class EvaluationResult {
        private final GroupElement evaluatedElement;
        private final Proof proof;
        private final GroupElement publicKey;

        public EvaluationResult(GroupElement evaluatedElement, Proof proof, GroupElement publicKey) {
            this.evaluatedElement = evaluatedElement;
            this.proof = proof;
            this.publicKey = publicKey;
        }

        /**
         * Returns the evaluated element (server's contribution to the PRF output).
         */
        public GroupElement getEvaluatedElement() {
            return evaluatedElement;
        }

        /**
         * Returns the DLEQ proof (null for base OPRF mode).
         */
        public Proof getProof() {
            return proof;
        }

        /**
         * Returns the public key used for evaluation.
         * For POPRF, this is the tweaked public key.
         */
        public GroupElement getPublicKey() {
            return publicKey;
        }

        /**
         * Serializes the evaluated element to bytes.
         */
        public byte[] getEvaluatedElementBytes() {
            return evaluatedElement.toBytes();
        }

        /**
         * Serializes the proof to bytes (returns null for base mode).
         */
        public byte[] getProofBytes() {
            return proof != null ? proof.toBytes() : null;
        }
    }
}
