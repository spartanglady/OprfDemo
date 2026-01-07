package com.oprf.demo.model;

import jakarta.validation.constraints.NotBlank;

/**
 * Request to evaluate a blinded element.
 */
public record OprfRequest(
        @NotBlank(message = "Blinded element is required")
        String blindedElement  // Base64-encoded blinded curve point
) {}
