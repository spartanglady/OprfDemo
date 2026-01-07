package com.oprf.demo.service;

import com.oprf.OprfKeyManager;
import com.oprf.OprfMode;
import com.oprf.OprfServer;
import com.oprf.OprfServer.ServerResponse;
import com.oprf.demo.model.OprfResponse;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Service managing the OPRF server with key versioning support.
 * Uses VOPRF mode so clients can verify the server's correctness.
 */
@Service
public class OprfService {

    private static final Logger log = LoggerFactory.getLogger(OprfService.class);

    private OprfKeyManager keyManager;

    @PostConstruct
    public void init() {
        // Create VOPRF key manager - clients can verify proofs
        this.keyManager = new OprfKeyManager(OprfMode.VERIFIABLE);

        log.info("OPRF Key Manager initialized with version {} and public key: {}...",
                keyManager.getCurrentVersion(),
                bytesToHex(keyManager.getCurrentPublicKey()).substring(0, 16));
    }

    /**
     * Returns the current key version.
     */
    public int getCurrentKeyVersion() {
        return keyManager.getCurrentVersion();
    }

    /**
     * Returns the server's public key for the current version (Base64 encoded).
     * Clients need this to verify DLEQ proofs.
     */
    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(keyManager.getCurrentPublicKey());
    }

    /**
     * Returns the public key for a specific version.
     */
    public String getPublicKey(int version) {
        byte[] key = keyManager.getPublicKey(version);
        return key != null ? Base64.getEncoder().encodeToString(key) : null;
    }

    /**
     * Evaluates a blinded element from a client using the current key version.
     *
     * @param blindedElementBase64 the blinded curve point (Base64)
     * @return evaluation response with proof and key version
     */
    public OprfResponse evaluate(String blindedElementBase64) {
        byte[] blindedElement = Base64.getDecoder().decode(blindedElementBase64);

        OprfKeyManager.CurrentKey currentKey = keyManager.getCurrentKey();
        ServerResponse response = currentKey.server().evaluate(blindedElement);

        return new OprfResponse(
                Base64.getEncoder().encodeToString(response.getEvaluatedElement()),
                Base64.getEncoder().encodeToString(response.getProof()),
                Base64.getEncoder().encodeToString(response.getPublicKey()),
                currentKey.version()
        );
    }

    /**
     * Rotates to a new randomly generated key.
     *
     * @return the new key version
     */
    public KeyRotationResult rotateKey() {
        OprfKeyManager.CurrentKey oldKey = keyManager.getCurrentKey();
        int oldVersion = oldKey.version();
        byte[] oldPublicKey = oldKey.server().getPublicKey();

        int newVersion = keyManager.rotateKey();
        byte[] newPublicKey = keyManager.getCurrentPublicKey();

        log.info("Key rotated: version {} -> {}", oldVersion, newVersion);
        log.info("Old public key: {}...", bytesToHex(oldPublicKey).substring(0, 16));
        log.info("New public key: {}...", bytesToHex(newPublicKey).substring(0, 16));

        return new KeyRotationResult(
                oldVersion,
                newVersion,
                Base64.getEncoder().encodeToString(oldPublicKey),
                Base64.getEncoder().encodeToString(newPublicKey),
                keyManager.getAvailableVersions().size()
        );
    }

    /**
     * Gets metadata about all available key versions.
     */
    public List<KeyVersionInfo> getKeyVersions() {
        return keyManager.getKeyMetadata().stream()
                .map(m -> new KeyVersionInfo(
                        m.version(),
                        Base64.getEncoder().encodeToString(m.publicKey()),
                        m.isCurrent()
                ))
                .collect(Collectors.toList());
    }

    /**
     * Checks if a specific key version exists.
     */
    public boolean hasKeyVersion(int version) {
        return keyManager.hasVersion(version);
    }

    /**
     * Returns the OPRF server for a specific version (for re-derivation during migration).
     */
    public OprfServer getServer(int version) {
        return keyManager.getServer(version);
    }

    /**
     * Retires an old key version.
     *
     * @param version the version to retire
     * @return true if retired, false if version didn't exist
     * @throws IllegalArgumentException if trying to retire current version
     */
    public boolean retireKeyVersion(int version) {
        boolean retired = keyManager.retireVersion(version);
        if (retired) {
            log.info("Key version {} retired", version);
        }
        return retired;
    }

    /**
     * Exports all keys for backup (use with caution!).
     */
    public Map<Integer, String> exportKeys() {
        return keyManager.exportAllKeys().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> Base64.getEncoder().encodeToString(e.getValue())
                ));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Result of a key rotation operation.
     */
    public record KeyRotationResult(
            int previousVersion,
            int newVersion,
            String previousPublicKey,
            String newPublicKey,
            int totalVersions
    ) {}

    /**
     * Information about a key version.
     */
    public record KeyVersionInfo(
            int version,
            String publicKey,
            boolean isCurrent
    ) {}
}
