package com.oprf;

import com.oprf.core.KeyPair;
import com.oprf.exception.OprfException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages versioned OPRF keys for key rotation support.
 *
 * <p>This class maintains multiple key versions to support graceful key rotation:
 * <ul>
 *   <li>One "current" key for new evaluations</li>
 *   <li>Multiple "previous" keys for verifying old tokens</li>
 * </ul>
 *
 * <h2>Usage Example:</h2>
 * <pre>{@code
 * // Create manager with initial key
 * OprfKeyManager manager = new OprfKeyManager(OprfMode.VERIFIABLE);
 *
 * // Get current server for evaluations
 * OprfServer server = manager.getCurrentServer();
 * int version = manager.getCurrentVersion();
 *
 * // Rotate to a new key
 * manager.rotateKey();
 *
 * // Old versions still accessible for verification
 * OprfServer oldServer = manager.getServer(1);
 * }</pre>
 *
 * <h2>Key Rotation Strategy:</h2>
 * <ol>
 *   <li>Call {@link #rotateKey()} to generate new key</li>
 *   <li>New token derivations use new key (via {@link #getCurrentServer()})</li>
 *   <li>Existing tokens remain valid (use {@link #getServer(int)} with stored version)</li>
 *   <li>Clients naturally re-derive on next interaction</li>
 *   <li>After transition period, call {@link #retireVersion(int)} to remove old keys</li>
 * </ol>
 */
public class OprfKeyManager {

    private final OprfMode mode;
    private final Map<Integer, OprfServer> servers;
    private final Map<Integer, byte[]> privateKeys;
    private final Object rotationLock = new Object();
    private volatile CurrentKey currentKey;

    /**
     * Creates a new key manager with a randomly generated initial key.
     *
     * @param mode the OPRF mode to use for all keys
     */
    public OprfKeyManager(OprfMode mode) {
        this.mode = Objects.requireNonNull(mode, "Mode cannot be null");
        this.servers = new ConcurrentHashMap<>();
        this.privateKeys = new ConcurrentHashMap<>();

        // Generate initial key (version 1)
        OprfServer server = OprfServer.create(mode);
        servers.put(1, server);
        privateKeys.put(1, server.exportPrivateKey());
        this.currentKey = new CurrentKey(1, server);
    }

    /**
     * Creates a key manager with an existing key as version 1.
     *
     * @param mode       the OPRF mode
     * @param privateKey the 32-byte private key for version 1
     */
    public OprfKeyManager(OprfMode mode, byte[] privateKey) {
        this.mode = Objects.requireNonNull(mode, "Mode cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");

        this.servers = new ConcurrentHashMap<>();
        this.privateKeys = new ConcurrentHashMap<>();

        OprfServer server = OprfServer.create(mode, privateKey);
        servers.put(1, server);
        privateKeys.put(1, privateKey.clone());
        this.currentKey = new CurrentKey(1, server);
    }

    /**
     * Creates a key manager and restores multiple key versions.
     *
     * @param mode           the OPRF mode
     * @param versionedKeys  map of version number to private key bytes
     * @param currentVersion the version to use as current
     */
    public OprfKeyManager(OprfMode mode, Map<Integer, byte[]> versionedKeys, int currentVersion) {
        this.mode = Objects.requireNonNull(mode, "Mode cannot be null");
        Objects.requireNonNull(versionedKeys, "Versioned keys cannot be null");

        if (versionedKeys.isEmpty()) {
            throw new IllegalArgumentException("Must provide at least one key");
        }
        if (!versionedKeys.containsKey(currentVersion)) {
            throw new IllegalArgumentException("Current version " + currentVersion + " not in provided keys");
        }

        this.servers = new ConcurrentHashMap<>();
        this.privateKeys = new ConcurrentHashMap<>();

        for (Map.Entry<Integer, byte[]> entry : versionedKeys.entrySet()) {
            int version = entry.getKey();
            byte[] key = entry.getValue();
            servers.put(version, OprfServer.create(mode, key));
            privateKeys.put(version, key.clone());
        }
        OprfServer currentServer = servers.get(currentVersion);
        this.currentKey = new CurrentKey(currentVersion, currentServer);
    }

    /**
     * Rotates to a new randomly generated key.
     * The new key becomes the current version, old keys remain accessible.
     *
     * @return the new version number
     */
    public int rotateKey() {
        OprfServer newServer = OprfServer.create(mode);
        return rotateToServer(newServer, newServer.exportPrivateKey());
    }

    /**
     * Rotates to a new key derived from a seed (deterministic).
     *
     * @param seed 32-byte secret seed
     * @param info optional public info
     * @return the new version number
     */
    public int rotateKeyDeterministic(byte[] seed, byte[] info) {
        OprfServer newServer = OprfServer.derive(mode, seed, info);
        return rotateToServer(newServer, newServer.exportPrivateKey());
    }

    /**
     * Rotates to a specific provided key.
     *
     * @param privateKey the 32-byte private key for the new version
     * @return the new version number
     */
    public int rotateKeyTo(byte[] privateKey) {
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        OprfServer newServer = OprfServer.create(mode, privateKey);
        return rotateToServer(newServer, privateKey.clone());
    }

    /**
     * Returns the current (latest) OPRF server.
     */
    public OprfServer getCurrentServer() {
        return currentKey.server();
    }

    /**
     * Returns the current version number.
     */
    public int getCurrentVersion() {
        return currentKey.version();
    }

    /**
     * Returns a consistent snapshot of the current key and version.
     */
    public CurrentKey getCurrentKey() {
        return currentKey;
    }

    /**
     * Returns the OPRF server for a specific version.
     *
     * @param version the key version
     * @return the server, or null if version doesn't exist
     */
    public OprfServer getServer(int version) {
        return servers.get(version);
    }

    /**
     * Returns the OPRF server for a specific version, throwing if not found.
     *
     * @param version the key version
     * @return the server
     * @throws OprfException if version doesn't exist
     */
    public OprfServer getServerOrThrow(int version) {
        OprfServer server = servers.get(version);
        if (server == null) {
            throw OprfException.invalidKeyVersion(version);
        }
        return server;
    }

    /**
     * Checks if a specific version exists.
     */
    public boolean hasVersion(int version) {
        return servers.containsKey(version);
    }

    /**
     * Returns all available version numbers.
     */
    public Set<Integer> getAvailableVersions() {
        return Collections.unmodifiableSet(servers.keySet());
    }

    /**
     * Returns the public key for a specific version.
     *
     * @param version the key version
     * @return the public key bytes, or null if version doesn't exist
     */
    public byte[] getPublicKey(int version) {
        OprfServer server = servers.get(version);
        return server != null ? server.getPublicKey() : null;
    }

    /**
     * Returns the public key for the current version.
     */
    public byte[] getCurrentPublicKey() {
        return currentKey.server().getPublicKey();
    }

    /**
     * Exports the private key for a specific version.
     * Handle with care - this is sensitive!
     *
     * @param version the key version
     * @return the private key bytes, or null if version doesn't exist
     */
    public byte[] exportPrivateKey(int version) {
        byte[] key = privateKeys.get(version);
        return key != null ? key.clone() : null;
    }

    /**
     * Exports all keys for backup/persistence.
     *
     * @return map of version to private key bytes
     */
    public Map<Integer, byte[]> exportAllKeys() {
        Map<Integer, byte[]> result = new HashMap<>();
        for (Map.Entry<Integer, byte[]> entry : privateKeys.entrySet()) {
            result.put(entry.getKey(), entry.getValue().clone());
        }
        return result;
    }

    /**
     * Retires (removes) an old key version.
     * Cannot retire the current version.
     *
     * @param version the version to retire
     * @return true if the version was retired, false if it didn't exist
     * @throws IllegalArgumentException if trying to retire current version
     */
    public boolean retireVersion(int version) {
        if (version == currentKey.version()) {
            throw new IllegalArgumentException("Cannot retire current version");
        }
        boolean removed = servers.remove(version) != null;
        privateKeys.remove(version);
        return removed;
    }

    /**
     * Returns the OPRF mode for this manager.
     */
    public OprfMode getMode() {
        return mode;
    }

    /**
     * Returns a snapshot of key metadata (versions and public keys).
     * Useful for diagnostics without exposing private keys.
     */
    public List<KeyMetadata> getKeyMetadata() {
        int current = currentKey.version();
        List<KeyMetadata> metadata = new ArrayList<>();
        for (Integer version : servers.keySet()) {
            OprfServer server = servers.get(version);
            metadata.add(new KeyMetadata(
                    version,
                    server.getPublicKey(),
                    version == current
            ));
        }
        metadata.sort(Comparator.comparingInt(KeyMetadata::version));
        return metadata;
    }

    /**
     * Metadata about a key version.
     */
    public record KeyMetadata(
            int version,
            byte[] publicKey,
            boolean isCurrent
    ) {}

    /**
     * Snapshot of the current key version and server instance.
     */
    public record CurrentKey(int version, OprfServer server) {}

    private int rotateToServer(OprfServer server, byte[] privateKey) {
        Objects.requireNonNull(server, "Server cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        synchronized (rotationLock) {
            int newVersion = nextAvailableVersion();
            servers.put(newVersion, server);
            privateKeys.put(newVersion, privateKey.clone());
            currentKey = new CurrentKey(newVersion, server);
            return newVersion;
        }
    }

    private int nextAvailableVersion() {
        int candidate = currentKey != null ? currentKey.version() + 1 : 1;
        while (servers.containsKey(candidate)) {
            candidate++;
        }
        return candidate;
    }
}
