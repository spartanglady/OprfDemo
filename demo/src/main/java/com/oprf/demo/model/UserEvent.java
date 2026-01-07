package com.oprf.demo.model;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * A stored event record.
 */
public record UserEvent(
        String id,
        String userToken,
        String clientId,
        String eventType,
        String description,
        BigDecimal amount,
        Instant timestamp
) {
    public static UserEvent from(EventRequest request) {
        return new UserEvent(
                UUID.randomUUID().toString(),
                request.userToken(),
                request.clientId(),
                request.eventType(),
                request.description(),
                request.amount(),
                Instant.now()
        );
    }
}
