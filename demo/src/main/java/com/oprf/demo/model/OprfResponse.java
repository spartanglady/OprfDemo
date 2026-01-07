package com.oprf.demo.model;

/**
 * Response from OPRF evaluation.
 */
public record OprfResponse(
        String evaluatedElement,  // Base64-encoded evaluated point
        String proof,             // Base64-encoded DLEQ proof (for VOPRF)
        String publicKey,         // Base64-encoded server public key
        int keyVersion            // Key version used for this evaluation
) {
    /**
     * Constructor for backwards compatibility (defaults to version 1).
     */
    public OprfResponse(String evaluatedElement, String proof, String publicKey) {
        this(evaluatedElement, proof, publicKey, 1);
    }
}
