package com.oprf.demo.controller;

import com.oprf.demo.model.OprfRequest;
import com.oprf.demo.model.OprfResponse;
import com.oprf.demo.service.OprfService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller for OPRF operations.
 *
 * Clients use these endpoints to:
 * 1. Get the server's public key (for proof verification)
 * 2. Submit blinded elements for evaluation
 */
@RestController
@RequestMapping("/api/oprf")
public class OprfController {

    private static final Logger log = LoggerFactory.getLogger(OprfController.class);

    private final OprfService oprfService;

    public OprfController(OprfService oprfService) {
        this.oprfService = oprfService;
    }

    /**
     * GET /api/oprf/public-key
     *
     * Returns the server's public key and current key version.
     * Clients need this to verify DLEQ proofs.
     */
    @GetMapping("/public-key")
    public ResponseEntity<Map<String, Object>> getPublicKey() {
        log.debug("Public key requested");
        return ResponseEntity.ok(Map.of(
                "publicKey", oprfService.getPublicKey(),
                "keyVersion", oprfService.getCurrentKeyVersion(),
                "mode", "VERIFIABLE",
                "suite", "P256-SHA256"
        ));
    }

    /**
     * POST /api/oprf/evaluate
     *
     * Evaluates a blinded element from a client.
     * The server cannot see the original input (it's blinded).
     *
     * Request body:
     * {
     *   "blindedElement": "base64-encoded-point"
     * }
     *
     * Response:
     * {
     *   "evaluatedElement": "base64-encoded-point",
     *   "proof": "base64-encoded-dleq-proof",
     *   "publicKey": "base64-encoded-public-key",
     *   "keyVersion": 1
     * }
     */
    @PostMapping("/evaluate")
    public ResponseEntity<OprfResponse> evaluate(@Valid @RequestBody OprfRequest request) {
        log.debug("OPRF evaluation requested");

        OprfResponse response = oprfService.evaluate(request.blindedElement());

        log.debug("OPRF evaluation complete (key version {})", response.keyVersion());
        return ResponseEntity.ok(response);
    }
}
