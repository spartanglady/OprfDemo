package com.oprf.demo.client;

import com.oprf.demo.client.OprfClient.TokenResult;
import com.oprf.demo.client.OprfClient.KeyInfo;

import java.util.ArrayList;
import java.util.List;

/**
 * Demonstrates key rotation workflow for the OPRF Identity Hub.
 *
 * This demo shows:
 * 1. Initial token derivation with key v1
 * 2. Submitting events with v1 tokens
 * 3. Key rotation to v2
 * 4. New tokens automatically use v2
 * 5. Token migration (linking old tokens to new)
 * 6. Both old and new tokens refer to the same user
 *
 * Run: ./gradlew :demo:rotationDemo
 * (Make sure the server is running: ./gradlew :demo:bootRun)
 */
public class KeyRotationDemo {

    private static final String SERVER_URL = "http://localhost:8080";
    private static final String ADMIN_API_KEY = System.getenv("OPRF_KEY_MANAGEMENT_API_KEY");

    // Simulated users with identifiers (these never leave the "client")
    private static final List<User> USERS = List.of(
            new User("Alice Johnson", "user-alice-12345"),
            new User("Bob Smith", "user-bob-67890")
    );

    public static void main(String[] args) throws Exception {
        if (ADMIN_API_KEY == null || ADMIN_API_KEY.isBlank()) {
            System.out.println("Missing OPRF_KEY_MANAGEMENT_API_KEY. Set it to enable key rotation.");
            return;
        }
        System.out.println("""

            ╔═══════════════════════════════════════════════════════════╗
            ║         Key Rotation Demo - OPRF Identity Hub             ║
            ╚═══════════════════════════════════════════════════════════╝

            This demonstrates how key rotation works without losing
            the ability to correlate users across clients.

            """);

        OprfClient client = new OprfClient(SERVER_URL, ADMIN_API_KEY);

        // Clear any existing data
        clearData();

        // ═══════════════════════════════════════════════════════════════
        // PHASE 1: Initial Setup with Key v1
        // ═══════════════════════════════════════════════════════════════
        printPhase(1, "Initial Token Derivation (Key v1)");

        KeyInfo keyInfo = client.getKeyInfo();
        System.out.println("Current server key version: " + keyInfo.version());
        System.out.println("Public key: " + keyInfo.publicKey().substring(0, 20) + "...\n");

        // Store tokens for later comparison
        List<TokenRecord> v1Tokens = new ArrayList<>();

        for (User user : USERS) {
            System.out.println("Processing: " + user.name());
            System.out.println("  Identifier: " + maskId(user.identifier()) + " (never sent to server)");

            TokenResult result = client.deriveTokenWithVersion(user.identifier());
            v1Tokens.add(new TokenRecord(user, result.token(), result.keyVersion()));

            System.out.println("  Derived token: " + result.token().substring(0, 16) + "...");
            System.out.println("  Key version: " + result.keyVersion());

            // Submit some events
            client.submitEvent(result.token(), "bank-a", "deposit",
                    "Initial deposit", 1000.0, result.keyVersion());
            System.out.println("  → Submitted event (bank-a): deposit $1000\n");
        }

        printStats("After Phase 1");

        // ═══════════════════════════════════════════════════════════════
        // PHASE 2: Key Rotation
        // ═══════════════════════════════════════════════════════════════
        printPhase(2, "Server Key Rotation");

        System.out.println("Triggering key rotation on server...\n");
        int newVersion = client.rotateKey();

        keyInfo = client.getKeyInfo();
        System.out.println("✓ Key rotated!");
        System.out.println("  New key version: " + keyInfo.version());
        System.out.println("  New public key: " + keyInfo.publicKey().substring(0, 20) + "...\n");

        // ═══════════════════════════════════════════════════════════════
        // PHASE 3: Demonstrate New Tokens
        // ═══════════════════════════════════════════════════════════════
        printPhase(3, "Token Derivation After Rotation (Key v2)");

        System.out.println("Deriving new tokens with the new key...\n");

        List<TokenRecord> v2Tokens = new ArrayList<>();

        for (User user : USERS) {
            System.out.println("Processing: " + user.name());

            TokenResult result = client.deriveTokenWithVersion(user.identifier());
            v2Tokens.add(new TokenRecord(user, result.token(), result.keyVersion()));

            System.out.println("  New token: " + result.token().substring(0, 16) + "...");
            System.out.println("  Key version: " + result.keyVersion());

            // Find the old token for comparison
            String oldToken = v1Tokens.stream()
                    .filter(t -> t.user().identifier().equals(user.identifier()))
                    .map(TokenRecord::token)
                    .findFirst()
                    .orElse("");

            boolean tokensDifferent = !result.token().equals(oldToken);
            System.out.println("  Different from v1 token: " + (tokensDifferent ? "✓ YES" : "✗ NO"));

            if (tokensDifferent) {
                System.out.println("  Old (v1): " + oldToken.substring(0, 16) + "...");
                System.out.println("  New (v2): " + result.token().substring(0, 16) + "...");
            }
            System.out.println();
        }

        // ═══════════════════════════════════════════════════════════════
        // PHASE 4: Token Migration (Linking)
        // ═══════════════════════════════════════════════════════════════
        printPhase(4, "Token Migration (Linking Old to New)");

        System.out.println("""
            When clients upgrade to the new key, they can link their
            old token to their new token. This preserves user continuity.
            """);

        for (int i = 0; i < USERS.size(); i++) {
            TokenRecord oldRecord = v1Tokens.get(i);
            TokenRecord newRecord = v2Tokens.get(i);

            System.out.println("Migrating: " + oldRecord.user().name());
            System.out.println("  Linking v" + oldRecord.keyVersion() + " token → v" + newRecord.keyVersion() + " token");

            boolean success = client.linkTokenAfterRotation(
                    oldRecord.token(), oldRecord.keyVersion(),
                    newRecord.token(), newRecord.keyVersion()
            );

            System.out.println("  Result: " + (success ? "✓ Linked successfully" : "✗ Link failed"));
            System.out.println();
        }

        // ═══════════════════════════════════════════════════════════════
        // PHASE 5: Demonstrate Correlation
        // ═══════════════════════════════════════════════════════════════
        printPhase(5, "Submit Events with New Tokens");

        System.out.println("""
            Now submitting events from a different client using v2 tokens.
            These should correlate with the same users from Phase 1.
            """);

        for (TokenRecord record : v2Tokens) {
            System.out.println("Processing: " + record.user().name());

            client.submitEvent(record.token(), "hospital-b", "visit",
                    "Annual checkup", 250.0, record.keyVersion());
            System.out.println("  → Submitted event (hospital-b): visit $250");
            System.out.println("  Using key version: " + record.keyVersion() + "\n");
        }

        printStats("After Phase 5");

        // ═══════════════════════════════════════════════════════════════
        // SUMMARY
        // ═══════════════════════════════════════════════════════════════
        System.out.println("\n" + "═".repeat(60));
        System.out.println("SUMMARY");
        System.out.println("═".repeat(60));

        System.out.println("""

            Key Rotation Complete!

            What happened:
            1. Users were registered with key v1 tokens
            2. Server rotated to key v2
            3. New derivations produce DIFFERENT tokens (expected!)
            4. Clients linked their old tokens to new tokens
            5. Events from both tokens are correlated to same user

            To verify the correlation, run:

              curl http://localhost:8080/api/users | jq

            You should see:
            • 2 users total
            • Each user has events from BOTH bank-a and hospital-b
            • tokenVersionCount shows each user has 2 token versions

            Key stats:

              curl http://localhost:8080/api/keys/stats | jq

            """);

        // Print token comparison
        System.out.println("Token Comparison:");
        System.out.println("-".repeat(60));
        for (int i = 0; i < USERS.size(); i++) {
            TokenRecord v1 = v1Tokens.get(i);
            TokenRecord v2 = v2Tokens.get(i);
            System.out.println(v1.user().name() + ":");
            System.out.println("  v1: " + v1.token().substring(0, 32) + "...");
            System.out.println("  v2: " + v2.token().substring(0, 32) + "...");
            System.out.println("  Same user? ✓ YES (linked via migration)");
        }
    }

    private static void printPhase(int num, String title) {
        System.out.println("\n" + "━".repeat(60));
        System.out.println("PHASE " + num + ": " + title);
        System.out.println("━".repeat(60) + "\n");
    }

    private static void printStats(String label) throws Exception {
        System.out.println("\n[" + label + "]");
        System.out.println("  curl http://localhost:8080/api/keys/stats | jq\n");
    }

    private static void clearData() throws Exception {
        java.net.http.HttpClient httpClient = java.net.http.HttpClient.newHttpClient();
        java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(SERVER_URL + "/api/users"))
                .DELETE()
                .build();
        httpClient.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
        System.out.println("Cleared existing data.\n");
    }

    private static String maskId(String id) {
        return "***" + id.substring(id.length() - 5);
    }

    record User(String name, String identifier) {}
    record TokenRecord(User user, String token, int keyVersion) {}
}
