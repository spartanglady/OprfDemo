package com.oprf.demo.client;

import com.oprf.CipherSuite;
import com.oprf.OprfMode;
import com.oprf.core.GroupElement;
import com.oprf.core.Proof;
import com.oprf.core.Scalar;
import com.oprf.demo.model.OprfResponse;
import com.oprf.protocol.DleqProver;
import com.oprf.protocol.HashToCurve;
import com.oprf.util.ContextString;
import com.oprf.util.Serialization;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Client-side OPRF implementation.
 *
 * This class demonstrates what a real client would do:
 * 1. Hash the sensitive identifier to a curve point
 * 2. Blind it with a random scalar
 * 3. Send to server for evaluation
 * 4. Unblind the result
 * 5. Derive a deterministic token
 */
public class OprfClient {

    private final String serverUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String adminApiKey;

    public OprfClient(String serverUrl) {
        this(serverUrl, null);
    }

    public OprfClient(String serverUrl, String adminApiKey) {
        this.serverUrl = serverUrl;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
        this.adminApiKey = adminApiKey;
    }

    /**
     * Result of a token derivation including key version info.
     */
    public record TokenResult(String token, int keyVersion) {}

    /**
     * Derives an OPRF token from a sensitive identifier.
     *
     * The server never sees the actual identifier - only a blinded version.
     *
     * @param sensitiveId the sensitive identifier
     * @return hex-encoded deterministic token
     */
    public String deriveToken(String sensitiveId) throws Exception {
        return deriveTokenWithVersion(sensitiveId).token();
    }

    /**
     * Derives an OPRF token and returns the key version used.
     *
     * @param sensitiveId the sensitive identifier (e.g., "123-45-6789")
     * @return token result with key version
     */
    public TokenResult deriveTokenWithVersion(String sensitiveId) throws Exception {
        // Step 1: Hash the identifier to a curve point
        byte[] inputBytes = sensitiveId.getBytes(StandardCharsets.UTF_8);
        GroupElement hashedPoint = HashToCurve.hashToCurve(
                inputBytes,
                CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE)
        );

        // Step 2: Generate random blinding factor
        Scalar blind = Scalar.random();

        // Step 3: Blind the point: B = blind * H(id)
        GroupElement blindedElement = hashedPoint.multiply(blind);

        // Step 4: Send to server for evaluation
        String blindedBase64 = Base64.getEncoder().encodeToString(blindedElement.toBytes());
        OprfResponse response = callOprfEvaluate(blindedBase64);

        byte[] evaluatedBytes = Base64.getDecoder().decode(response.evaluatedElement());
        byte[] proofBytes = Base64.getDecoder().decode(response.proof());
        byte[] publicKeyBytes = Base64.getDecoder().decode(response.publicKey());

        // Step 5: Unblind the result: Y = (1/blind) * Z
        GroupElement evaluatedElement = GroupElement.fromBytes(evaluatedBytes);
        GroupElement serverPublicKey = GroupElement.fromBytes(publicKeyBytes);
        Proof proof = Proof.fromBytes(proofBytes);

        // Verify the server's proof (VOPRF)
        DleqProver prover = new DleqProver(OprfMode.VERIFIABLE);
        boolean valid = prover.verifyProof(
                GroupElement.generator(),
                serverPublicKey,
                blindedElement,
                evaluatedElement,
                proof
        );
        if (!valid) {
            throw new RuntimeException("OPRF proof verification failed");
        }

        GroupElement unblindedResult = evaluatedElement.multiply(blind.invert());

        // Step 6: Derive final token using RFC 9497 Finalize
        String token = deriveTokenHash(inputBytes, unblindedResult);
        return new TokenResult(token, response.keyVersion());
    }

    /**
     * Calls the server's OPRF evaluate endpoint.
     */
    private OprfResponse callOprfEvaluate(String blindedElementBase64) throws Exception {
        String requestBody = """
                {"blindedElement": "%s"}
                """.formatted(blindedElementBase64);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/oprf/evaluate"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("OPRF evaluation failed: " + response.body());
        }

        return objectMapper.readValue(response.body(), OprfResponse.class);
    }

    /**
     * Derives the final token hash.
     */
    private String deriveTokenHash(byte[] input, GroupElement unblindedElement) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] unblindedBytes = unblindedElement.toBytes();
            byte[] hashInput = ContextString.concat(
                    Serialization.i2osp2(input.length), input,
                    Serialization.i2osp2(unblindedBytes.length), unblindedBytes,
                    ContextString.finalizeDst(OprfMode.VERIFIABLE)
            );
            byte[] hash = digest.digest(hashInput);

            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("Hash failed", e);
        }
    }

    /**
     * Submits an event to the hub.
     */
    public void submitEvent(String userToken, String clientId, String eventType,
                            String description, double amount, Integer keyVersion) throws Exception {
        if (keyVersion == null) {
            throw new IllegalArgumentException("Key version is required for event submission");
        }
        String requestBody;
        requestBody = """
                {
                    "userToken": "%s",
                    "clientId": "%s",
                    "eventType": "%s",
                    "description": "%s",
                    "amount": %.2f,
                    "keyVersion": %d
                }
                """.formatted(userToken, clientId, eventType, description, amount, keyVersion);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/events"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Event submission failed: " + response.body());
        }
    }

    /**
     * Triggers a key rotation on the server.
     *
     * @return the new key version
     */
    public int rotateKey() throws Exception {
        if (adminApiKey == null || adminApiKey.isBlank()) {
            throw new IllegalArgumentException("Admin API key is required to rotate keys");
        }
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/keys/rotate"))
                .header("Content-Type", "application/json")
                .header("X-Admin-Key", adminApiKey)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Key rotation failed: " + response.body());
        }

        // Parse newVersion from response
        var json = objectMapper.readTree(response.body());
        return json.get("newVersion").asInt();
    }

    /**
     * Gets current key info from the server.
     */
    public KeyInfo getKeyInfo() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/oprf/public-key"))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to get key info: " + response.body());
        }

        var json = objectMapper.readTree(response.body());
        return new KeyInfo(
                json.get("keyVersion").asInt(),
                json.get("publicKey").asText()
        );
    }

    /**
     * Links a new token (after rotation) to an existing user.
     */
    public boolean linkTokenAfterRotation(String oldToken, int oldVersion,
                                          String newToken, int newVersion) throws Exception {
        String requestBody = """
                {
                    "oldToken": "%s",
                    "oldVersion": %d,
                    "newToken": "%s",
                    "newVersion": %d
                }
                """.formatted(oldToken, oldVersion, newToken, newVersion);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/users/link-token"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

        return response.statusCode() == 200;
    }

    public record KeyInfo(int version, String publicKey) {}
}
