package com.oprf;

import com.oprf.core.GroupElement;
import com.oprf.core.KeyPair;
import com.oprf.core.Proof;
import com.oprf.exception.OprfException;
import com.oprf.protocol.BlindEvaluate;
import com.oprf.protocol.BlindEvaluate.EvaluationResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Main API for OPRF (Oblivious Pseudorandom Function) server operations.
 *
 * <p>Implements RFC 9497 OPRF protocol in three modes:
 * <ul>
 *   <li>{@link OprfMode#BASE} - Basic OPRF without proofs</li>
 *   <li>{@link OprfMode#VERIFIABLE} - VOPRF with DLEQ proofs</li>
 *   <li>{@link OprfMode#PARTIAL} - POPRF with public metadata support</li>
 * </ul>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * // Create a VOPRF server with a new random key
 * OprfServer server = OprfServer.create(OprfMode.VERIFIABLE);
 *
 * // Evaluate a blinded element from the client
 * byte[] blindedInput = ...; // received from client
 * ServerResponse response = server.evaluate(blindedInput);
 *
 * // Send response back to client
 * byte[] evaluatedElement = response.getEvaluatedElement();
 * byte[] proof = response.getProof(); // null for BASE mode
 * }</pre>
 *
 * <p>The server's public key can be shared with clients for VOPRF verification:
 * <pre>{@code
 * byte[] publicKey = server.getPublicKey();
 * }</pre>
 */
public final class OprfServer {

    private final OprfMode mode;
    private final KeyPair keyPair;
    private final BlindEvaluate evaluator;

    private OprfServer(OprfMode mode, KeyPair keyPair) {
        this.mode = mode;
        this.keyPair = keyPair;
        this.evaluator = new BlindEvaluate(mode, keyPair);
    }

    /**
     * Creates a new OPRF server with a randomly generated key.
     *
     * @param mode the OPRF mode (BASE, VERIFIABLE, or PARTIAL)
     * @return a new OprfServer instance
     */
    public static OprfServer create(OprfMode mode) {
        Objects.requireNonNull(mode, "Mode cannot be null");
        return new OprfServer(mode, KeyPair.generate());
    }

    /**
     * Creates an OPRF server using deterministic key derivation.
     *
     * @param mode the OPRF mode (BASE, VERIFIABLE, or PARTIAL)
     * @param seed 32-byte secret seed
     * @param info optional public info (may be empty)
     * @return a new OprfServer instance
     */
    public static OprfServer derive(OprfMode mode, byte[] seed, byte[] info) {
        Objects.requireNonNull(mode, "Mode cannot be null");
        Objects.requireNonNull(seed, "Seed cannot be null");
        Objects.requireNonNull(info, "Info cannot be null");
        return new OprfServer(mode, KeyPair.deriveKeyPair(mode, seed, info));
    }

    /**
     * Creates an OPRF server from an existing private key.
     *
     * @param mode           the OPRF mode
     * @param privateKeyBytes the 32-byte private key
     * @return a new OprfServer instance
     * @throws OprfException if the private key is invalid
     */
    public static OprfServer create(OprfMode mode, byte[] privateKeyBytes) {
        Objects.requireNonNull(mode, "Mode cannot be null");
        Objects.requireNonNull(privateKeyBytes, "Private key cannot be null");
        return new OprfServer(mode, KeyPair.fromPrivateKeyBytes(privateKeyBytes));
    }

    /**
     * Returns the OPRF mode this server is configured for.
     */
    public OprfMode getMode() {
        return mode;
    }

    /**
     * Returns the server's public key in compressed SEC1 format (33 bytes).
     * Clients need this to verify VOPRF proofs.
     */
    public byte[] getPublicKey() {
        return keyPair.exportPublicKey();
    }

    /**
     * Exports the server's private key (32 bytes).
     * Store securely - this is the server's secret!
     */
    public byte[] exportPrivateKey() {
        return keyPair.exportPrivateKey();
    }

    /**
     * Evaluates a blinded element from the client.
     *
     * @param blindedElement the 33-byte compressed blinded element
     * @return the server's response including evaluated element and optional proof
     * @throws OprfException if the input is invalid
     */
    public ServerResponse evaluate(byte[] blindedElement) {
        if (mode == OprfMode.PARTIAL) {
            throw new IllegalStateException("Info parameter required in PARTIAL (POPRF) mode");
        }
        Objects.requireNonNull(blindedElement, "Blinded element cannot be null");
        GroupElement element = GroupElement.fromBytes(blindedElement);
        EvaluationResult result = evaluator.evaluate(element);
        return new ServerResponse(result);
    }

    /**
     * Evaluates a blinded element with public info (POPRF mode only).
     *
     * @param blindedElement the 33-byte compressed blinded element
     * @param info           the public info parameter
     * @return the server's response
     * @throws OprfException         if the input is invalid
     * @throws IllegalStateException if not in PARTIAL mode
     */
    public ServerResponse evaluate(byte[] blindedElement, byte[] info) {
        if (mode != OprfMode.PARTIAL) {
            throw new IllegalStateException("Info parameter only supported in PARTIAL (POPRF) mode");
        }
        Objects.requireNonNull(blindedElement, "Blinded element cannot be null");
        Objects.requireNonNull(info, "Info cannot be null");
        if (info.length > 0xFFFF) {
            throw new IllegalArgumentException("Info length exceeds 65535 bytes");
        }

        GroupElement element = GroupElement.fromBytes(blindedElement);
        EvaluationResult result = evaluator.evaluate(element, info);
        return new ServerResponse(result);
    }

    /**
     * Evaluates multiple blinded elements in a batch.
     * More efficient than individual evaluations when proofs are required.
     *
     * @param blindedElements list of 33-byte compressed blinded elements
     * @return list of server responses
     * @throws OprfException if any input is invalid
     */
    public List<ServerResponse> evaluateBatch(List<byte[]> blindedElements) {
        if (mode == OprfMode.PARTIAL) {
            throw new IllegalStateException("Info parameter required in PARTIAL (POPRF) mode");
        }
        Objects.requireNonNull(blindedElements, "Blinded elements cannot be null");
        if (blindedElements.isEmpty()) {
            throw new IllegalArgumentException("Must provide at least one blinded element");
        }

        List<GroupElement> elements = new ArrayList<>(blindedElements.size());
        for (byte[] bytes : blindedElements) {
            elements.add(GroupElement.fromBytes(bytes));
        }

        List<EvaluationResult> results = evaluator.evaluateBatch(elements);

        List<ServerResponse> responses = new ArrayList<>(results.size());
        for (EvaluationResult result : results) {
            responses.add(new ServerResponse(result));
        }
        return responses;
    }

    /**
     * Evaluates multiple blinded elements with public info (POPRF mode only).
     *
     * @param blindedElements list of blinded elements
     * @param info            the public info parameter
     * @return list of server responses
     */
    public List<ServerResponse> evaluateBatch(List<byte[]> blindedElements, byte[] info) {
        if (mode != OprfMode.PARTIAL) {
            throw new IllegalStateException("Info parameter only supported in PARTIAL (POPRF) mode");
        }
        Objects.requireNonNull(blindedElements, "Blinded elements cannot be null");
        Objects.requireNonNull(info, "Info cannot be null");
        if (info.length > 0xFFFF) {
            throw new IllegalArgumentException("Info length exceeds 65535 bytes");
        }

        List<GroupElement> elements = new ArrayList<>(blindedElements.size());
        for (byte[] bytes : blindedElements) {
            elements.add(GroupElement.fromBytes(bytes));
        }

        List<EvaluationResult> results = evaluator.evaluateBatch(elements, info);

        List<ServerResponse> responses = new ArrayList<>(results.size());
        for (EvaluationResult result : results) {
            responses.add(new ServerResponse(result));
        }
        return responses;
    }

    /**
     * Response from the OPRF server containing the evaluated element
     * and optional DLEQ proof.
     */
    public static final class ServerResponse {
        private final EvaluationResult result;

        private ServerResponse(EvaluationResult result) {
            this.result = result;
        }

        /**
         * Returns the evaluated element in compressed SEC1 format (33 bytes).
         * The client uses this to complete the OPRF computation.
         */
        public byte[] getEvaluatedElement() {
            return result.getEvaluatedElementBytes();
        }

        /**
         * Returns the DLEQ proof in serialized format (64 bytes).
         * Returns null for BASE mode.
         */
        public byte[] getProof() {
            return result.getProofBytes();
        }

        /**
         * Returns the public key used for this evaluation (33 bytes).
         * For POPRF, this is the tweaked public key.
         */
        public byte[] getPublicKey() {
            return result.getPublicKey().toBytes();
        }

        /**
         * Checks if this response includes a DLEQ proof.
         */
        public boolean hasProof() {
            return result.getProof() != null;
        }

        /**
         * Returns the GroupElement form of the evaluated element.
         */
        public GroupElement getEvaluatedElementAsGroupElement() {
            return result.getEvaluatedElement();
        }

        /**
         * Returns the Proof object (null for BASE mode).
         */
        public Proof getProofObject() {
            return result.getProof();
        }
    }
}
