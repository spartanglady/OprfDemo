package com.oprf.demo.model;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.math.BigDecimal;

/**
 * Request to submit an event linked to a user token.
 */
public record EventRequest(
        @NotBlank(message = "User token is required")
        String userToken,         // OPRF-derived token (hex string)

        @NotBlank(message = "Client ID is required")
        String clientId,          // Which client is submitting (e.g., "bank-a", "hospital-b")

        @NotBlank(message = "Event type is required")
        String eventType,         // Type of event (e.g., "transaction", "visit", "claim")

        String description,       // Human-readable description

        BigDecimal amount,        // Optional amount (for transactions, claims, etc.)

        @NotNull(message = "Key version is required")
        @Min(value = 1, message = "Key version must be >= 1")
        Integer keyVersion        // Key version used to derive this token
) {
}
