package com.oprf.demo.model;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Aggregated user profile based on OPRF token.
 */
public record UserProfile(
        String token,                  // The OPRF-derived token (primary key)
        Set<String> knownClients,      // All clients that have submitted events for this user
        List<UserEvent> events,        // All events across all clients
        Instant firstSeen,             // When this token was first seen
        Instant lastSeen               // Most recent activity
) {}
