package com.oprf.demo.controller;

import com.oprf.demo.model.EventRequest;
import com.oprf.demo.model.LinkTokenRequest;
import com.oprf.demo.model.UserEvent;
import com.oprf.demo.model.UserProfile;
import com.oprf.demo.service.OprfService;
import com.oprf.demo.service.UserRepository;
import com.oprf.demo.service.UserRepository.Stats;
import com.oprf.demo.service.UserRepository.UserSummary;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST controller for event submission and user lookup.
 *
 * Clients submit events with OPRF-derived tokens (not raw identifiers).
 * The hub correlates events by token.
 */
@RestController
@RequestMapping("/api")
public class EventController {

    private static final Logger log = LoggerFactory.getLogger(EventController.class);

    private final UserRepository userRepository;
    private final OprfService oprfService;

    public EventController(UserRepository userRepository, OprfService oprfService) {
        this.userRepository = userRepository;
        this.oprfService = oprfService;
    }

    /**
     * POST /api/events
     *
     * Submit an event linked to a user token.
     *
     * Request body:
     * {
     *   "userToken": "hex-encoded-oprf-token",
     *   "clientId": "bank-a",
     *   "eventType": "transaction",
     *   "description": "Wire transfer",
     *   "amount": 1500.00,
     *   "keyVersion": 1
     * }
     */
    @PostMapping("/events")
    public ResponseEntity<UserEvent> submitEvent(@Valid @RequestBody EventRequest request) {
        log.info("Event received from client '{}' for token {}...",
                request.clientId(), request.userToken().substring(0, Math.min(16, request.userToken().length())));

        int keyVersion = request.keyVersion();
        if (!oprfService.hasKeyVersion(keyVersion)) {
            return ResponseEntity.badRequest().build();
        }

        UserEvent event = userRepository.saveEvent(request);

        return ResponseEntity.ok(event);
    }

    /**
     * GET /api/users
     *
     * List all known user tokens with summary information.
     */
    @GetMapping("/users")
    public ResponseEntity<Map<String, Object>> listUsers() {
        List<UserSummary> users = userRepository.listAllUsers();
        Stats stats = userRepository.getStats();

        return ResponseEntity.ok(Map.of(
                "stats", stats,
                "users", users
        ));
    }

    /**
     * GET /api/users/{token}
     *
     * Get full profile for a user token, including all events from all clients.
     */
    @GetMapping("/users/{token}")
    public ResponseEntity<UserProfile> getUser(@PathVariable String token) {
        return userRepository.findByToken(token)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/stats
     *
     * Get repository statistics.
     */
    @GetMapping("/stats")
    public ResponseEntity<Stats> getStats() {
        return ResponseEntity.ok(userRepository.getStats());
    }

    /**
     * DELETE /api/users
     *
     * Clear all data (for testing/demo purposes).
     */
    @DeleteMapping("/users")
    public ResponseEntity<Map<String, String>> clearAll() {
        userRepository.clear();
        log.info("All user data cleared");
        return ResponseEntity.ok(Map.of("status", "cleared"));
    }

    /**
     * POST /api/users/link-token
     *
     * Links a new token (from key rotation) to an existing user.
     * This allows clients to migrate their tokens after a key rotation.
     *
     * Request body:
     * {
     *   "oldToken": "hex-encoded-old-token",
     *   "oldVersion": 1,
     *   "newToken": "hex-encoded-new-token",
     *   "newVersion": 2
     * }
     */
    @PostMapping("/users/link-token")
    public ResponseEntity<Map<String, Object>> linkToken(@Valid @RequestBody LinkTokenRequest request) {
        String oldToken = request.oldToken();
        int oldVersion = request.oldVersion();
        String newToken = request.newToken();
        int newVersion = request.newVersion();

        if (oldVersion == newVersion) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "failed",
                    "error", "Old and new key versions must differ"
            ));
        }

        if (oldToken.equals(newToken)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "failed",
                    "error", "Old and new tokens must differ"
            ));
        }

        if (!oprfService.hasKeyVersion(oldVersion)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "failed",
                    "error", "Old key version not found",
                    "oldVersion", oldVersion
            ));
        }

        if (!oprfService.hasKeyVersion(newVersion)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "failed",
                    "error", "New key version not found",
                    "newVersion", newVersion
            ));
        }

        boolean success = userRepository.linkTokenAfterRotation(
                oldToken, oldVersion, newToken, newVersion);

        if (success) {
            log.info("Token linked: v{} -> v{}", oldVersion, newVersion);
            return ResponseEntity.ok(Map.of(
                    "status", "linked",
                    "oldVersion", oldVersion,
                    "newVersion", newVersion
            ));
        } else {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "failed",
                    "error", "Old token not found"
            ));
        }
    }
}
