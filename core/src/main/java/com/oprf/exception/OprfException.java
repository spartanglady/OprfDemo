package com.oprf.exception;

/**
 * Exception thrown when OPRF operations fail.
 */
public class OprfException extends RuntimeException {

    public OprfException(String message) {
        super(message);
    }

    public OprfException(String message, Throwable cause) {
        super(message, cause);
    }

    public static OprfException invalidPoint(String reason) {
        return new OprfException("Invalid elliptic curve point: " + reason);
    }

    public static OprfException invalidScalar(String reason) {
        return new OprfException("Invalid scalar value: " + reason);
    }

    public static OprfException serializationError(String reason) {
        return new OprfException("Serialization error: " + reason);
    }

    public static OprfException inputValidationError(String reason) {
        return new OprfException("Input validation error: " + reason);
    }

    public static OprfException deriveKeyPairError() {
        return new OprfException("DeriveKeyPair failed");
    }

    public static OprfException proofVerificationFailed() {
        return new OprfException("DLEQ proof verification failed");
    }

    public static OprfException invalidKeyVersion(int version) {
        return new OprfException("Key version not found: " + version);
    }
}
