package com.oprf.demo.controller;

import com.oprf.demo.service.OprfService;
import com.oprf.demo.service.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

/**
 * REST controller for key management operations.
 *
 * Provides endpoints for:
 * 1. Viewing key versions
 * 2. Rotating keys
 * 3. Viewing key rotation statistics
 *
 * NOTE: In production, these endpoints should be secured
 * and only accessible to administrators.
 */
@RestController
@RequestMapping("/api/keys")
public class KeyManagementController {

    private static final Logger log = LoggerFactory.getLogger(KeyManagementController.class);

    private final OprfService oprfService;
    private final UserRepository userRepository;
    private final byte[] adminApiKey;
    private final boolean keyManagementEnabled;

    public KeyManagementController(OprfService oprfService, UserRepository userRepository,
                                   @Value("${oprf.keyManagement.apiKey:}") String adminApiKey) {
        this.oprfService = oprfService;
        this.userRepository = userRepository;
        this.keyManagementEnabled = adminApiKey != null && !adminApiKey.isBlank();
        this.adminApiKey = this.keyManagementEnabled
                ? adminApiKey.getBytes(StandardCharsets.UTF_8)
                : new byte[0];
    }

    /**
     * GET /api/keys
     *
     * Lists all available key versions.
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> listKeys(
            @RequestHeader(value = "X-Admin-Key", required = false) String adminKey) {
        ResponseEntity<Map<String, Object>> unauthorized = requireAdminKey(adminKey);
        if (unauthorized != null) {
            return unauthorized;
        }
        List<OprfService.KeyVersionInfo> versions = oprfService.getKeyVersions();
        UserRepository.Stats stats = userRepository.getStats();

        return ResponseEntity.ok(Map.of(
                "currentVersion", oprfService.getCurrentKeyVersion(),
                "versions", versions,
                "tokensByVersion", stats.tokensByKeyVersion()
        ));
    }

    /**
     * GET /api/keys/{version}
     *
     * Gets details for a specific key version.
     */
    @GetMapping("/{version}")
    public ResponseEntity<Map<String, Object>> getKey(@PathVariable int version,
                                                      @RequestHeader(value = "X-Admin-Key", required = false) String adminKey) {
        ResponseEntity<Map<String, Object>> unauthorized = requireAdminKey(adminKey);
        if (unauthorized != null) {
            return unauthorized;
        }
        if (!oprfService.hasKeyVersion(version)) {
            return ResponseEntity.notFound().build();
        }

        String publicKey = oprfService.getPublicKey(version);
        boolean isCurrent = version == oprfService.getCurrentKeyVersion();

        return ResponseEntity.ok(Map.of(
                "version", version,
                "publicKey", publicKey,
                "isCurrent", isCurrent
        ));
    }

    /**
     * POST /api/keys/rotate
     *
     * Rotates to a new key version.
     * The old key remains available for verification of existing tokens.
     */
    @PostMapping("/rotate")
    public ResponseEntity<OprfService.KeyRotationResult> rotateKey(
            @RequestHeader(value = "X-Admin-Key", required = false) String adminKey) {
        if (!isAuthorized(adminKey)) {
            return ResponseEntity.status(403).build();
        }
        log.info("Key rotation requested");

        OprfService.KeyRotationResult result = oprfService.rotateKey();

        log.info("Key rotation complete: v{} -> v{}", result.previousVersion(), result.newVersion());

        return ResponseEntity.ok(result);
    }

    /**
     * DELETE /api/keys/{version}
     *
     * Retires an old key version.
     * Cannot retire the current version.
     * Tokens derived with this key will no longer be verifiable.
     */
    @DeleteMapping("/{version}")
    public ResponseEntity<Map<String, Object>> retireKey(@PathVariable int version,
                                                         @RequestHeader(value = "X-Admin-Key", required = false) String adminKey) {
        ResponseEntity<Map<String, Object>> unauthorized = requireAdminKey(adminKey);
        if (unauthorized != null) {
            return unauthorized;
        }
        if (version == oprfService.getCurrentKeyVersion()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Cannot retire current key version",
                    "currentVersion", version
            ));
        }

        boolean retired = oprfService.retireKeyVersion(version);

        if (!retired) {
            return ResponseEntity.notFound().build();
        }

        log.info("Key version {} retired", version);

        return ResponseEntity.ok(Map.of(
                "retired", version,
                "currentVersion", oprfService.getCurrentKeyVersion(),
                "remainingVersions", oprfService.getKeyVersions().size()
        ));
    }

    /**
     * GET /api/keys/stats
     *
     * Returns statistics about key usage.
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats(
            @RequestHeader(value = "X-Admin-Key", required = false) String adminKey) {
        ResponseEntity<Map<String, Object>> unauthorized = requireAdminKey(adminKey);
        if (unauthorized != null) {
            return unauthorized;
        }
        UserRepository.Stats repoStats = userRepository.getStats();

        return ResponseEntity.ok(Map.of(
                "currentKeyVersion", oprfService.getCurrentKeyVersion(),
                "totalKeyVersions", oprfService.getKeyVersions().size(),
                "totalUsers", repoStats.totalUsers(),
                "totalEvents", repoStats.totalEvents(),
                "tokensByKeyVersion", repoStats.tokensByKeyVersion()
        ));
    }

    private ResponseEntity<Map<String, Object>> requireAdminKey(String providedKey) {
        if (!keyManagementEnabled) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "Key management is disabled",
                    "hint", "Configure oprf.keyManagement.apiKey to enable"
            ));
        }
        if (!isAuthorized(providedKey)) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "Invalid admin key"
            ));
        }
        return null;
    }

    private boolean isAuthorized(String providedKey) {
        if (!keyManagementEnabled || providedKey == null) {
            return false;
        }
        byte[] provided = providedKey.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(adminApiKey, provided);
    }
}
