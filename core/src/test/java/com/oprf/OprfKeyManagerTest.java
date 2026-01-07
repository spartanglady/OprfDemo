package com.oprf;

import com.oprf.exception.OprfException;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class OprfKeyManagerTest {

    @Test
    void testInitialKeyGeneration() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);

        assertEquals(1, manager.getCurrentVersion());
        assertNotNull(manager.getCurrentServer());
        assertNotNull(manager.getCurrentPublicKey());
        assertEquals(33, manager.getCurrentPublicKey().length);
        assertTrue(manager.hasVersion(1));
        assertEquals(Set.of(1), manager.getAvailableVersions());
    }

    @Test
    void testRotateKey() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);
        byte[] publicKey1 = manager.getCurrentPublicKey();

        int newVersion = manager.rotateKey();

        assertEquals(2, newVersion);
        assertEquals(2, manager.getCurrentVersion());
        assertTrue(manager.hasVersion(1));
        assertTrue(manager.hasVersion(2));
        assertEquals(Set.of(1, 2), manager.getAvailableVersions());

        // Public keys should be different
        byte[] publicKey2 = manager.getCurrentPublicKey();
        assertFalse(java.util.Arrays.equals(publicKey1, publicKey2));

        // Old server still accessible
        assertNotNull(manager.getServer(1));
        assertArrayEquals(publicKey1, manager.getServer(1).getPublicKey());
    }

    @Test
    void testRotateSkipsExistingVersion() {
        OprfMode mode = OprfMode.VERIFIABLE;
        OprfServer server1 = OprfServer.create(mode);
        OprfServer server2 = OprfServer.create(mode);

        Map<Integer, byte[]> keys = new HashMap<>();
        keys.put(1, server1.exportPrivateKey());
        keys.put(2, server2.exportPrivateKey());

        OprfKeyManager manager = new OprfKeyManager(mode, keys, 1);
        int newVersion = manager.rotateKey();

        assertEquals(3, newVersion);
        assertArrayEquals(server2.getPublicKey(), manager.getPublicKey(2));
    }

    @Test
    void testMultipleRotations() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);

        manager.rotateKey(); // v2
        manager.rotateKey(); // v3
        manager.rotateKey(); // v4

        assertEquals(4, manager.getCurrentVersion());
        assertEquals(Set.of(1, 2, 3, 4), manager.getAvailableVersions());

        // All servers accessible
        for (int v = 1; v <= 4; v++) {
            assertNotNull(manager.getServer(v));
        }
    }

    @Test
    void testRestoreFromPrivateKey() {
        // Create first manager, get its key
        OprfKeyManager original = new OprfKeyManager(OprfMode.VERIFIABLE);
        byte[] privateKey = original.exportPrivateKey(1);
        byte[] publicKey = original.getCurrentPublicKey();

        // Restore to new manager
        OprfKeyManager restored = new OprfKeyManager(OprfMode.VERIFIABLE, privateKey);

        assertEquals(1, restored.getCurrentVersion());
        assertArrayEquals(publicKey, restored.getCurrentPublicKey());
    }

    @Test
    void testRestoreMultipleVersions() {
        // Create original with multiple versions
        OprfKeyManager original = new OprfKeyManager(OprfMode.VERIFIABLE);
        original.rotateKey(); // v2
        original.rotateKey(); // v3

        Map<Integer, byte[]> allKeys = original.exportAllKeys();
        byte[] publicKey2 = original.getPublicKey(2);

        // Restore with v2 as current
        OprfKeyManager restored = new OprfKeyManager(OprfMode.VERIFIABLE, allKeys, 2);

        assertEquals(2, restored.getCurrentVersion());
        assertEquals(Set.of(1, 2, 3), restored.getAvailableVersions());
        assertArrayEquals(publicKey2, restored.getCurrentPublicKey());
    }

    @Test
    void testEvaluationWithDifferentVersions() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);

        // Get blinded element
        byte[] input = "test-input".getBytes();
        com.oprf.core.GroupElement hashedPoint = com.oprf.protocol.HashToCurve.hashToCurve(
                input, CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE));
        com.oprf.core.Scalar blind = com.oprf.core.Scalar.random();
        byte[] blindedElement = hashedPoint.multiply(blind).toBytes();

        // Evaluate with v1
        OprfServer.ServerResponse response1 = manager.getServer(1).evaluate(blindedElement);
        byte[] evaluated1 = response1.getEvaluatedElement();

        // Rotate and evaluate with v2
        manager.rotateKey();
        OprfServer.ServerResponse response2 = manager.getServer(2).evaluate(blindedElement);
        byte[] evaluated2 = response2.getEvaluatedElement();

        // Results should be different (different keys)
        assertFalse(java.util.Arrays.equals(evaluated1, evaluated2));

        // v1 should still give same result
        OprfServer.ServerResponse response1Again = manager.getServer(1).evaluate(blindedElement);
        assertArrayEquals(evaluated1, response1Again.getEvaluatedElement());
    }

    @Test
    void testRetireVersion() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);
        manager.rotateKey(); // v2
        manager.rotateKey(); // v3

        assertTrue(manager.retireVersion(1));
        assertFalse(manager.hasVersion(1));
        assertNull(manager.getServer(1));
        assertEquals(Set.of(2, 3), manager.getAvailableVersions());
    }

    @Test
    void testCannotRetireCurrentVersion() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);

        assertThrows(IllegalArgumentException.class, () -> manager.retireVersion(1));
    }

    @Test
    void testGetServerOrThrow() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);

        assertNotNull(manager.getServerOrThrow(1));
        assertThrows(OprfException.class, () -> manager.getServerOrThrow(999));
    }

    @Test
    void testKeyMetadata() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);
        manager.rotateKey(); // v2

        var metadata = manager.getKeyMetadata();

        assertEquals(2, metadata.size());

        var v1Meta = metadata.get(0);
        assertEquals(1, v1Meta.version());
        assertFalse(v1Meta.isCurrent());
        assertNotNull(v1Meta.publicKey());

        var v2Meta = metadata.get(1);
        assertEquals(2, v2Meta.version());
        assertTrue(v2Meta.isCurrent());
        assertNotNull(v2Meta.publicKey());
    }

    @Test
    void testDeterministicRotation() {
        byte[] seed = new byte[32];
        java.util.Arrays.fill(seed, (byte) 0x42);
        byte[] info = "test-info".getBytes();

        OprfKeyManager manager1 = new OprfKeyManager(OprfMode.VERIFIABLE);
        manager1.rotateKeyDeterministic(seed, info);

        OprfKeyManager manager2 = new OprfKeyManager(OprfMode.VERIFIABLE);
        manager2.rotateKeyDeterministic(seed, info);

        // Same seed+info should produce same key
        assertArrayEquals(
                manager1.getPublicKey(2),
                manager2.getPublicKey(2)
        );
    }

    @Test
    void testRotateKeyTo() {
        OprfKeyManager manager1 = new OprfKeyManager(OprfMode.VERIFIABLE);
        byte[] specificKey = manager1.exportPrivateKey(1);

        OprfKeyManager manager2 = new OprfKeyManager(OprfMode.VERIFIABLE);
        manager2.rotateKeyTo(specificKey);

        // v2 of manager2 should have same public key as v1 of manager1
        assertArrayEquals(
                manager1.getPublicKey(1),
                manager2.getPublicKey(2)
        );
    }

    @Test
    void testTokenConsistencyAcrossRotation() {
        OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);

        // Simulate token derivation with v1
        String ssn = "123-45-6789";
        String token1 = deriveToken(manager.getServer(1), ssn);

        // Rotate key
        manager.rotateKey();

        // Same SSN with v1 should still produce same token
        String token1Again = deriveToken(manager.getServer(1), ssn);
        assertEquals(token1, token1Again);

        // Same SSN with v2 should produce different token
        String token2 = deriveToken(manager.getServer(2), ssn);
        assertNotEquals(token1, token2);
    }

    @Test
    void testAllModes() {
        for (OprfMode mode : OprfMode.values()) {
            OprfKeyManager manager = new OprfKeyManager(mode);
            assertEquals(mode, manager.getMode());
            assertEquals(1, manager.getCurrentVersion());
            assertNotNull(manager.getCurrentServer());

            manager.rotateKey();
            assertEquals(2, manager.getCurrentVersion());
        }
    }

    /**
     * Helper to derive a token using the OPRF protocol.
     */
    private String deriveToken(OprfServer server, String input) {
        try {
            // Hash to curve
            com.oprf.core.GroupElement hashedPoint = com.oprf.protocol.HashToCurve.hashToCurve(
                    input.getBytes(), CipherSuite.getHashToCurveDST(server.getMode()));

            // Blind
            com.oprf.core.Scalar blind = com.oprf.core.Scalar.random();
            com.oprf.core.GroupElement blindedElement = hashedPoint.multiply(blind);

            // Evaluate
            OprfServer.ServerResponse response = server.evaluate(blindedElement.toBytes());
            com.oprf.core.GroupElement evaluatedElement =
                    com.oprf.core.GroupElement.fromBytes(response.getEvaluatedElement());

            // Unblind
            com.oprf.core.GroupElement unblinded = evaluatedElement.multiply(blind.invert());

            // Finalize (simplified - just hash for testing)
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            digest.update(input.getBytes());
            digest.update(unblinded.toBytes());
            byte[] hash = digest.digest();

            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
