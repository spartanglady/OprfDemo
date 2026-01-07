package com.oprf.demo.client;

import java.util.List;
import java.util.Random;

/**
 * Simulates multiple clients submitting events for users.
 *
 * Demonstrates that:
 * 1. Different clients derive the SAME token for the SAME identifier
 * 2. The server correlates all events by token
 * 3. No identifier ever leaves the client
 *
 * Run: ./gradlew :demo:simulateClients
 * (Make sure the server is running: ./gradlew :demo:bootRun)
 */
public class ClientSimulator {

    private static final String SERVER_URL = "http://localhost:8080";

    // Simulated users with identifiers (these never leave the "client")
    private static final List<User> USERS = List.of(
            new User("Alice Johnson", "user-alice-12345"),
            new User("Bob Smith", "user-bob-67890"),
            new User("Carol White", "user-carol-24680")
    );

    // Simulated clients
    private static final List<Client> CLIENTS = List.of(
            new Client("acme-bank", "Bank"),
            new Client("city-hospital", "Hospital"),
            new Client("shield-insurance", "Insurance")
    );

    public static void main(String[] args) throws Exception {
        System.out.println("""

            ╔═══════════════════════════════════════════════════════════╗
            ║         Client Simulator - OPRF Identity Demo             ║
            ╚═══════════════════════════════════════════════════════════╝

            This simulates three clients (Bank, Hospital, Insurance) each
            submitting events for the same users. The server correlates
            them WITHOUT ever seeing the identifiers.

            """);

        OprfClient oprfClient = new OprfClient(SERVER_URL);
        Random random = new Random(42); // Deterministic for demo

        // Each client processes each user
        for (Client client : CLIENTS) {
            System.out.println("━".repeat(60));
            System.out.println("Client: " + client.name() + " (" + client.type() + ")");
            System.out.println("━".repeat(60));

            for (User user : USERS) {
                System.out.println("\n  Processing: " + user.name());
                System.out.println("  Identifier: " + maskId(user.identifier()) + " (masked - never sent to server)");

                // Derive token using OPRF
                OprfClient.TokenResult tokenResult = oprfClient.deriveTokenWithVersion(user.identifier());
                String token = tokenResult.token();
                int keyVersion = tokenResult.keyVersion();
                System.out.println("  Derived token: " + token.substring(0, 16) + "...");

                // Submit some events for this user
                int eventCount = random.nextInt(3) + 1;
                for (int i = 0; i < eventCount; i++) {
                    Event event = generateEvent(client, random);
                    oprfClient.submitEvent(token, client.name(), event.type(),
                            event.description(), event.amount(), keyVersion);
                    System.out.println("    → Submitted: " + event.type() + " - " + event.description());
                }
            }
            System.out.println();
        }

        // Show correlation summary
        System.out.println("\n" + "═".repeat(60));
        System.out.println("CORRELATION DEMO");
        System.out.println("═".repeat(60));
        System.out.println("""

            Now check the server to see how events are correlated:

              curl http://localhost:8080/api/users | jq

            You'll see that:
            • Each user has a single token
            • Events from ALL clients are linked to that token
            • The server never knew the identifiers - only the tokens!

            To see a specific user's full profile:

              curl http://localhost:8080/api/users/<token> | jq

            """);

        // Print a quick summary
        printSummary(oprfClient);
    }

    private static void printSummary(OprfClient client) throws Exception {
        System.out.println("Quick verification - same identifier = same token:");
        System.out.println("-".repeat(50));

        for (User user : USERS) {
            String token1 = client.deriveToken(user.identifier());
            String token2 = client.deriveToken(user.identifier());
            boolean match = token1.equals(token2);
            System.out.printf("  %s: %s (consistent: %s)%n",
                    user.name(), token1.substring(0, 16) + "...", match ? "✓" : "✗");
        }
    }

    private static Event generateEvent(Client client, Random random) {
        return switch (client.type()) {
            case "Bank" -> {
                String[] types = {"deposit", "withdrawal", "transfer", "payment"};
                String[] descs = {"Payroll deposit", "ATM withdrawal", "Wire transfer", "Bill payment"};
                int idx = random.nextInt(types.length);
                yield new Event(types[idx], descs[idx], random.nextDouble() * 5000);
            }
            case "Hospital" -> {
                String[] types = {"visit", "lab", "procedure", "prescription"};
                String[] descs = {"Annual checkup", "Blood work", "X-ray imaging", "Medication refill"};
                int idx = random.nextInt(types.length);
                yield new Event(types[idx], descs[idx], random.nextDouble() * 1000);
            }
            case "Insurance" -> {
                String[] types = {"claim", "premium", "inquiry", "update"};
                String[] descs = {"Medical claim", "Premium payment", "Coverage inquiry", "Policy update"};
                int idx = random.nextInt(types.length);
                yield new Event(types[idx], descs[idx], random.nextDouble() * 2000);
            }
            default -> new Event("generic", "Generic event", 0);
        };
    }

    private static String maskId(String id) {
        return "***" + id.substring(id.length() - 5);
    }

    record User(String name, String identifier) {}
    record Client(String name, String type) {}
    record Event(String type, String description, double amount) {}
}
