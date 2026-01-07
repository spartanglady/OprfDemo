package com.oprf.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Identity Hub - Privacy-Preserving Cross-Client Identity Correlation
 *
 * This application demonstrates how OPRF can be used to correlate user records
 * across multiple clients without exposing sensitive identifiers.
 *
 * Flow:
 * 1. Client has user with sensitive identifier
 * 2. Client blinds identifier, sends to hub for OPRF evaluation
 * 3. Hub evaluates blindly (never sees identifier)
 * 4. Client unblinds to get deterministic token
 * 5. Client submits events with token (not identifier)
 * 6. Hub correlates all events by token
 *
 * Run: ./gradlew :demo:bootRun
 * Test: ./gradlew :demo:simulateClients (in another terminal)
 */
@SpringBootApplication
public class IdentityHubApplication {

    public static void main(String[] args) {
        System.out.println("""

                ╔═══════════════════════════════════════════════════════════╗
                ║       Identity Hub - OPRF Privacy-Preserving Demo         ║
                ╠═══════════════════════════════════════════════════════════╣
                ║                                                           ║
                ║  Endpoints:                                               ║
                ║    GET  /api/oprf/public-key     - Get server public key  ║
                ║    POST /api/oprf/evaluate       - Evaluate blinded input ║
                ║    POST /api/events              - Submit event with token║
                ║    GET  /api/users               - List all user tokens   ║
                ║    GET  /api/users/{token}       - Get user details       ║
                ║                                                           ║
                ║  Run client simulation:                                   ║
                ║    ./gradlew :demo:simulateClients                        ║
                ║                                                           ║
                ╚═══════════════════════════════════════════════════════════╝

                """);
        SpringApplication.run(IdentityHubApplication.class, args);
    }
}
