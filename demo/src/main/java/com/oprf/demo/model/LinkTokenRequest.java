package com.oprf.demo.model;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Request to link a token across key versions.
 */
public record LinkTokenRequest(
        @NotBlank(message = "Old token is required")
        String oldToken,

        @NotNull(message = "Old key version is required")
        @Min(value = 1, message = "Old key version must be >= 1")
        Integer oldVersion,

        @NotBlank(message = "New token is required")
        String newToken,

        @NotNull(message = "New key version is required")
        @Min(value = 1, message = "New key version must be >= 1")
        Integer newVersion
) {}
