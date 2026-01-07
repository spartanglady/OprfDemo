package com.oprf.demo.service;

import com.oprf.demo.model.EventRequest;
import com.oprf.demo.model.UserEvent;
import com.oprf.demo.model.UserProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory repository for user events with key versioning support.
 *
 * <p>Uses a composite key of (token, keyVersion) to support key rotation.
 * Users are identified by a stable userId that survives key rotation.
 */
@Repository
public class UserRepository {

    private static final Logger log = LoggerFactory.getLogger(UserRepository.class);

    // UserId -> UserRecord (the stable user storage)
    private final Map<String, UserRecord> usersById = new ConcurrentHashMap<>();

    // (Token, KeyVersion) -> UserId (index for lookup)
    private final Map<TokenKey, String> userIdByToken = new ConcurrentHashMap<>();

    /**
     * Stores an event linked to a user token.
     * If this is a new token, creates a new user. Otherwise, adds to existing user.
     */
    public UserEvent saveEvent(EventRequest request) {
        int keyVersion = Objects.requireNonNull(request.keyVersion(), "Key version is required");
        TokenKey tokenKey = new TokenKey(request.userToken(), keyVersion);

        // Find or create user
        String userId = userIdByToken.computeIfAbsent(tokenKey, tk -> {
            String newUserId = UUID.randomUUID().toString();
            UserRecord record = new UserRecord(newUserId, Instant.now());
            record.addToken(tk.token(), tk.keyVersion());
            usersById.put(newUserId, record);
            log.info("New user registered: {} with token {}... (key v{})",
                    newUserId.substring(0, 8), tk.token().substring(0, 16), tk.keyVersion());
            return newUserId;
        });

        // Add event to user record
        UserRecord record = usersById.get(userId);
        UserEvent event = UserEvent.from(request);
        record.addEvent(event);

        log.info("Event stored for user {}... from client '{}' (key v{})",
                userId.substring(0, 8), request.clientId(), keyVersion);

        return event;
    }

    /**
     * Links a new token (from key rotation) to an existing user.
     * Call this when a client re-derives their token with a new key version.
     *
     * @param oldToken     the previous token
     * @param oldVersion   the key version of the old token
     * @param newToken     the new token
     * @param newVersion   the key version of the new token
     * @return true if linked successfully, false if old token not found
     */
    public boolean linkTokenAfterRotation(String oldToken, int oldVersion,
                                          String newToken, int newVersion) {
        TokenKey oldKey = new TokenKey(oldToken, oldVersion);
        String userId = userIdByToken.get(oldKey);

        if (userId == null) {
            log.warn("Cannot link tokens: old token not found (v{})", oldVersion);
            return false;
        }

        TokenKey newKey = new TokenKey(newToken, newVersion);

        // Check if new token already exists
        String existingUserId = userIdByToken.get(newKey);
        if (existingUserId != null) {
            if (existingUserId.equals(userId)) {
                log.debug("Token already linked to same user");
                return true;
            } else {
                log.error("New token already linked to different user!");
                return false;
            }
        }

        // Link new token to existing user
        userIdByToken.put(newKey, userId);
        UserRecord record = usersById.get(userId);
        record.addToken(newToken, newVersion);

        log.info("Token migrated for user {}: v{} -> v{}",
                userId.substring(0, 8), oldVersion, newVersion);

        return true;
    }

    /**
     * Gets the full profile for a user by token.
     */
    public Optional<UserProfile> findByToken(String token) {
        return findByToken(token, null);
    }

    /**
     * Gets the full profile for a user by token and key version.
     */
    public Optional<UserProfile> findByToken(String token, Integer keyVersion) {
        String userId = null;

        if (keyVersion != null) {
            // Exact lookup
            userId = userIdByToken.get(new TokenKey(token, keyVersion));
        } else {
            // Search across all versions
            for (Map.Entry<TokenKey, String> entry : userIdByToken.entrySet()) {
                if (entry.getKey().token().equals(token)) {
                    userId = entry.getValue();
                    break;
                }
            }
        }

        if (userId == null) {
            return Optional.empty();
        }

        return findByUserId(userId);
    }

    /**
     * Gets the full profile for a user by userId.
     */
    public Optional<UserProfile> findByUserId(String userId) {
        UserRecord record = usersById.get(userId);
        if (record == null) {
            return Optional.empty();
        }

        List<UserEvent> eventsSnapshot = record.snapshotEvents();
        if (eventsSnapshot.isEmpty()) {
            return Optional.empty();
        }

        Set<String> clients = eventsSnapshot.stream()
                .map(UserEvent::clientId)
                .collect(Collectors.toSet());

        Instant lastSeen = eventsSnapshot.stream()
                .map(UserEvent::timestamp)
                .max(Instant::compareTo)
                .orElse(Instant.now());

        // Get the primary token (latest version)
        String primaryToken = record.getLatestToken();

        return Optional.of(new UserProfile(
                primaryToken,
                clients,
                eventsSnapshot,
                record.firstSeen,
                lastSeen
        ));
    }

    /**
     * Lists all known users with summary info.
     */
    public List<UserSummary> listAllUsers() {
        return usersById.values().stream()
                .map(record -> {
                    List<UserEvent> eventsSnapshot = record.snapshotEvents();
                    Set<String> clients = eventsSnapshot.stream()
                            .map(UserEvent::clientId)
                            .collect(Collectors.toSet());
                    return new UserSummary(
                            record.userId,
                            record.getLatestToken(),
                            record.getLatestKeyVersion(),
                            clients.size(),
                            eventsSnapshot.size(),
                            clients,
                            record.tokenVersions.size()
                    );
                })
                .sorted((a, b) -> Integer.compare(b.clientCount(), a.clientCount()))
                .collect(Collectors.toList());
    }

    /**
     * Summary of a user for listing purposes.
     */
    public record UserSummary(
            String userId,
            String token,
            int keyVersion,
            int clientCount,
            int eventCount,
            Set<String> clients,
            int tokenVersionCount
    ) {}

    /**
     * Clears all data (for testing).
     */
    public void clear() {
        usersById.clear();
        userIdByToken.clear();
    }

    /**
     * Returns statistics about the repository.
     */
    public Stats getStats() {
        int totalUsers = usersById.size();
        int totalEvents = 0;
        Set<String> allClients = new HashSet<>();
        long multiClientUsers = 0;

        for (UserRecord record : usersById.values()) {
            List<UserEvent> eventsSnapshot = record.snapshotEvents();
            totalEvents += eventsSnapshot.size();
            allClients.addAll(eventsSnapshot.stream()
                    .map(UserEvent::clientId)
                    .collect(Collectors.toSet()));
            long distinctClients = eventsSnapshot.stream()
                    .map(UserEvent::clientId)
                    .distinct()
                    .count();
            if (distinctClients > 1) {
                multiClientUsers++;
            }
        }

        // Count tokens by key version
        Map<Integer, Long> tokensByVersion = userIdByToken.keySet().stream()
                .collect(Collectors.groupingBy(TokenKey::keyVersion, Collectors.counting()));

        return new Stats(totalUsers, totalEvents, allClients.size(),
                (int) multiClientUsers, tokensByVersion);
    }

    public record Stats(
            int totalUsers,
            int totalEvents,
            int totalClients,
            int usersWithMultipleClients,
            Map<Integer, Long> tokensByKeyVersion
    ) {}

    /**
     * Composite key for token lookup.
     */
    private record TokenKey(String token, int keyVersion) {}

    /**
     * Internal user record.
     */
    private static class UserRecord {
        final String userId;
        final Instant firstSeen;
        final List<UserEvent> events = Collections.synchronizedList(new ArrayList<>());
        final Map<Integer, String> tokenVersions = new ConcurrentHashMap<>(); // version -> token

        UserRecord(String userId, Instant firstSeen) {
            this.userId = userId;
            this.firstSeen = firstSeen;
        }

        void addEvent(UserEvent event) {
            events.add(event);
        }

        void addToken(String token, int version) {
            tokenVersions.put(version, token);
        }

        List<UserEvent> snapshotEvents() {
            synchronized (events) {
                return new ArrayList<>(events);
            }
        }

        String getLatestToken() {
            return tokenVersions.entrySet().stream()
                    .max(Map.Entry.comparingByKey())
                    .map(Map.Entry::getValue)
                    .orElse(null);
        }

        int getLatestKeyVersion() {
            return tokenVersions.keySet().stream()
                    .max(Integer::compareTo)
                    .orElse(1);
        }
    }
}
