package com.oprf.core;

import com.oprf.OprfMode;
import com.oprf.exception.OprfException;
import com.oprf.protocol.HashToCurve;
import com.oprf.util.ContextString;
import com.oprf.util.Serialization;

import java.util.Objects;

/**
 * Represents an OPRF server key pair consisting of a private scalar (sk)
 * and public group element (pk = sk * G).
 */
public final class KeyPair {

    private final Scalar privateKey;
    private final GroupElement publicKey;

    private KeyPair(Scalar privateKey, GroupElement publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Generates a new random key pair.
     *
     * @return a new KeyPair with random private key
     */
    public static KeyPair generate() {
        Scalar sk = Scalar.random();
        GroupElement pk = GroupElement.generator().multiply(sk);
        return new KeyPair(sk, pk);
    }

    /**
     * Deterministically derives a key pair from a seed and optional info.
     *
     * @param mode the OPRF mode used for context string construction
     * @param seed 32-byte secret seed
     * @param info optional public info (may be empty)
     * @return a derived KeyPair
     */
    public static KeyPair deriveKeyPair(OprfMode mode, byte[] seed, byte[] info) {
        Objects.requireNonNull(mode, "Mode cannot be null");
        Objects.requireNonNull(seed, "Seed cannot be null");
        Objects.requireNonNull(info, "Info cannot be null");

        if (seed.length != 32) {
            throw new IllegalArgumentException("Seed must be 32 bytes");
        }
        if (info.length > 0xFFFF) {
            throw new IllegalArgumentException("Info length exceeds 65535 bytes");
        }

        byte[] deriveInput = ContextString.concat(
                seed,
                Serialization.i2osp2(info.length),
                info
        );

        int counter = 0;
        Scalar sk = Scalar.zero();
        while (sk.isZero()) {
            if (counter > 255) {
                throw OprfException.deriveKeyPairError();
            }
            byte[] input = ContextString.concat(deriveInput, new byte[]{(byte) counter});
            sk = HashToCurve.hashToScalar(input, ContextString.deriveKeyDst(mode));
            counter++;
        }

        GroupElement pk = GroupElement.generator().multiply(sk);
        return new KeyPair(sk, pk);
    }

    /**
     * Creates a key pair from an existing private key.
     *
     * @param privateKey the private key scalar
     * @return a new KeyPair
     * @throws OprfException if the private key is zero
     */
    public static KeyPair fromPrivateKey(Scalar privateKey) {
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        if (privateKey.isZero()) {
            throw OprfException.invalidScalar("Private key cannot be zero");
        }
        GroupElement pk = GroupElement.generator().multiply(privateKey);
        return new KeyPair(privateKey, pk);
    }

    /**
     * Creates a key pair from a serialized private key.
     *
     * @param privateKeyBytes the private key bytes
     * @return a new KeyPair
     */
    public static KeyPair fromPrivateKeyBytes(byte[] privateKeyBytes) {
        return fromPrivateKey(Scalar.fromBytes(privateKeyBytes));
    }

    /**
     * Returns the private key (secret scalar).
     */
    public Scalar getPrivateKey() {
        return privateKey;
    }

    /**
     * Returns the public key (pk = sk * G).
     */
    public GroupElement getPublicKey() {
        return publicKey;
    }

    /**
     * Serializes the private key to bytes.
     *
     * @return 32-byte private key
     */
    public byte[] exportPrivateKey() {
        return privateKey.toBytes();
    }

    /**
     * Serializes the public key to compressed point format.
     *
     * @return 33-byte compressed public key
     */
    public byte[] exportPublicKey() {
        return publicKey.toBytes();
    }

    @Override
    public String toString() {
        return "KeyPair[pk=" + publicKey + "]";
    }
}
