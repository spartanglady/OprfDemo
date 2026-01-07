# OPRF Server Library

A Java implementation of Oblivious Pseudorandom Functions (OPRF) per [RFC 9497](https://datatracker.ietf.org/doc/rfc9497/), with a practical demo for privacy-preserving cross-client identity correlation.

## Table of Contents

- [What is OPRF?](#what-is-oprf)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Identity Hub Demo](#identity-hub-demo)
- [Key Rotation Demo](#key-rotation-demo)
- [API Reference](#api-reference)
- [Library Usage](#library-usage)
- [Technical Details](#technical-details)
- [Deep Dive: Protocol Security](#deep-dive-protocol-security)
- [Server Data Model](#server-data-model)
- [Key Management](#key-management)

---

## What is OPRF?

### The Problem

Imagine you need to correlate user records across multiple organizations (banks, hospitals, insurance companies) using a sensitive identifier. But you can't:

1. Send raw identifiers over the network (security risk!)
2. Store identifiers in a central database (privacy violation!)
3. Let the central hub see the identifiers at all

### The Solution: OPRF

**OPRF (Oblivious Pseudorandom Function)** lets clients derive a deterministic token from sensitive data, where:

- The **server never sees** the sensitive input (it's "blinded")
- The **same input always produces the same token** (deterministic)
- **Different inputs produce different tokens** (pseudorandom)
- Clients can **verify the server behaved correctly** (verifiable)

### How It Works (Simple Analogy)

Think of it like a **secret stamp machine**:

```
You have: A sensitive identifier (e.g., "user-12345")
Server has: A secret stamp (the key)

Step 1: You put your identifier in an OPAQUE ENVELOPE (blind it)
Step 2: You send the sealed envelope to the server
Step 3: Server stamps the envelope WITHOUT OPENING IT
Step 4: Server returns the stamped envelope
Step 5: You open the envelope and see the stamp result

Magic result:
- Server stamped your identifier but NEVER SAW IT
- Anyone with the same identifier gets the SAME stamp
- Only this server's stamp works (can't forge it)
```

### OPRF Variants

| Mode | Description | Use Case |
|------|-------------|----------|
| **BASE** | Basic OPRF, no proofs | When you trust the server |
| **VERIFIABLE** | Includes cryptographic proof | When you need to verify server honesty |
| **PARTIAL** | Adds public context parameter | When you need context-specific tokens |

---

## Project Structure

```
oprf/
├── build.gradle                 # Root build configuration
├── settings.gradle              # Module includes
├── README.md
│
├── core/                        # OPRF Library (RFC 9497)
│   ├── build.gradle
│   └── src/
│       ├── main/java/com/oprf/
│       │   ├── OprfServer.java         # Main API
│       │   ├── OprfMode.java           # BASE, VERIFIABLE, PARTIAL
│       │   ├── CipherSuite.java        # P256-SHA256 configuration
│       │   ├── core/                   # Cryptographic primitives
│       │   ├── protocol/               # OPRF protocol implementation
│       │   └── exception/              # Custom exceptions
│       └── test/java/com/oprf/         # 48 unit tests
│
└── demo/                        # Identity Hub (Spring Boot)
    ├── build.gradle
    └── src/main/java/com/oprf/demo/
        ├── IdentityHubApplication.java  # Spring Boot app
        ├── controller/                  # REST endpoints
        ├── service/                     # Business logic
        ├── model/                       # DTOs
        └── client/                      # Client simulator
```

---

## Quick Start

### Prerequisites

- Java 21+
- Gradle (wrapper included)

### Build the Project

```bash
# Clone and build
git clone <repository-url>
cd oprf

# Build everything (includes running tests)
./gradlew build

# Run only tests
./gradlew :core:test
```

### Run the Identity Hub Demo

**Terminal 1 - Start the server:**
```bash
./gradlew :demo:bootRun
```

You'll see:
```
╔═══════════════════════════════════════════════════════════╗
║       Identity Hub - OPRF Privacy-Preserving Demo         ║
╠═══════════════════════════════════════════════════════════╣
║  Endpoints:                                               ║
║    GET  /api/oprf/public-key     - Get server public key  ║
║    POST /api/oprf/evaluate       - Evaluate blinded input ║
║    POST /api/events              - Submit event with token║
║    GET  /api/users               - List all user tokens   ║
║    GET  /api/users/{token}       - Get user details       ║
╚═══════════════════════════════════════════════════════════╝
```

**Terminal 2 - Run the client simulation:**
```bash
./gradlew :demo:simulateClients
```

This simulates 3 clients (Bank, Hospital, Insurance) each submitting events for 3 users.

---

## Identity Hub Demo

### Scenario

A central Identity Hub needs to correlate user records from multiple client organizations **without ever seeing sensitive identifiers**.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  ACME Bank  │     │City Hospital│     │  Insurance  │
│             │     │             │     │             │
│ Alice: ID   │     │ Alice: ID   │     │ Alice: ID   │
│ Bob: ID     │     │ Bob: ID     │     │ Bob: ID     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │  OPRF Protocol    │  OPRF Protocol    │  OPRF Protocol
       │  ID → Token       │  ID → Token       │  ID → Token
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────┐
│                    IDENTITY HUB                          │
│                                                          │
│  Token_Alice ──► [Bank events, Hospital events,         │
│                   Insurance events]                      │
│                                                          │
│  Token_Bob ────► [Bank events, Hospital events,         │
│                   Insurance events]                      │
│                                                          │
│  ✓ Hub correlates all records by token                  │
│  ✗ Hub NEVER sees any identifier                        │
└─────────────────────────────────────────────────────────┘
```

### Step-by-Step Walkthrough

#### 1. Start the Identity Hub Server

```bash
./gradlew :demo:bootRun
```

#### 2. Verify the Server is Running

```bash
curl http://localhost:8080/api/oprf/public-key
```

Response:
```json
{
  "publicKey": "A8owKqh0Z2c0eH4mQ9nknuXkK5RKx5nh39uHP4dahepg",
  "suite": "P256-SHA256",
  "mode": "VERIFIABLE"
}
```

#### 3. Run the Client Simulation

```bash
./gradlew :demo:simulateClients
```

You'll see output like:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Client: acme-bank (Bank)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Processing: Alice Johnson
  Identifier: ***masked*** (never sent to server)
  Derived token: 01b5ec0bc5e5ac33...
    → Submitted: deposit - Payroll deposit
    → Submitted: withdrawal - ATM withdrawal
```

**Key observation:** The identifier is masked because it **never leaves the client**. Only the derived token is sent to the server.

#### 4. View Correlated Users

```bash
curl http://localhost:8080/api/users
```

Response:
```json
{
  "stats": {
    "totalUsers": 3,
    "totalEvents": 24,
    "totalClients": 3,
    "usersWithMultipleClients": 3
  },
  "users": [
    {
      "token": "01b5ec0bc5e5ac33...",
      "clientCount": 3,
      "eventCount": 8,
      "clients": ["acme-bank", "city-hospital", "shield-insurance"]
    },
    ...
  ]
}
```

**Key observation:** Each user has events from **all 3 clients**, correlated by their OPRF token.

#### 5. View a Specific User's Profile

```bash
curl http://localhost:8080/api/users/01b5ec0bc5e5ac332fc53fd0e454e90846d85153485a577538df3b11c8e333ae
```

Response:
```json
{
  "token": "01b5ec0bc5e5ac33...",
  "knownClients": ["acme-bank", "city-hospital", "shield-insurance"],
  "events": [
    {
      "clientId": "acme-bank",
      "eventType": "deposit",
      "description": "Payroll deposit",
      "amount": 3416.12
    },
    {
      "clientId": "city-hospital",
      "eventType": "lab",
      "description": "Blood work",
      "amount": 209.77
    },
    {
      "clientId": "shield-insurance",
      "eventType": "claim",
      "description": "Medical claim",
      "amount": 1948.07
    }
  ]
}
```

**Key observation:** Alice's bank transactions, hospital visits, and insurance claims are all linked - **without the hub ever knowing her identifier**.

#### 6. Verify Token Consistency

The same identifier always produces the same token, regardless of which client derives it:

```
Quick verification - same identifier = same token:
--------------------------------------------------
  Alice Johnson: 01b5ec0bc5e5ac33... (consistent: ✓)
  Bob Smith: 0ceed583a8ebe560... (consistent: ✓)
  Carol White: c6e2d3a58f8e6cdc... (consistent: ✓)
```

---

## Key Rotation Demo

This demo shows how to rotate server keys while maintaining user correlation.

### Run the Demo

**Terminal 1 - Start the server:**
```bash
./gradlew :demo:bootRun
```

**Terminal 2 - Run the rotation demo:**
```bash
./gradlew :demo:rotationDemo
```

### What the Demo Shows

1. **Phase 1:** Derive tokens with key v1, submit events from Bank
2. **Phase 2:** Trigger server key rotation (v1 → v2)
3. **Phase 3:** Derive new tokens (different from v1, as expected)
4. **Phase 4:** Link old tokens to new tokens (token migration)
5. **Phase 5:** Submit events with v2 tokens from Hospital

### Demo Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 2: Server Key Rotation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Triggering key rotation on server...

✓ Key rotated!
  New key version: 2
  New public key: AjywrYvNOyAtQiAmbNy7...
```

### Verify Results

After the demo, check user correlation:

```bash
curl http://localhost:8080/api/users | jq
```

You'll see:
- **2 users** (Alice and Bob)
- Each user has events from **both** bank-a and hospital-b
- `tokenVersionCount: 2` - showing both v1 and v2 tokens are linked

```bash
curl -H "X-Admin-Key: $OPRF_KEY_MANAGEMENT_API_KEY" http://localhost:8080/api/keys/stats | jq
```

Shows token distribution across key versions:
```json
{
  "tokensByKeyVersion": {"1": 2, "2": 2},
  "totalUsers": 2,
  "totalEvents": 4
}
```

---

## API Reference

### OPRF Endpoints

#### Get Public Key
```http
GET /api/oprf/public-key
```

Returns the server's public key and current key version.

**Response:**
```json
{
  "publicKey": "base64-encoded-key",
  "keyVersion": 1,
  "suite": "P256-SHA256",
  "mode": "VERIFIABLE"
}
```

#### Evaluate Blinded Input
```http
POST /api/oprf/evaluate
Content-Type: application/json

{
  "blindedElement": "base64-encoded-blinded-point"
}
```

**Response:**
```json
{
  "evaluatedElement": "base64-encoded-point",
  "proof": "base64-encoded-dleq-proof",
  "publicKey": "base64-encoded-public-key",
  "keyVersion": 1
}
```

### Event Endpoints

#### Submit Event
```http
POST /api/events
Content-Type: application/json

{
  "userToken": "hex-encoded-oprf-token",
  "clientId": "acme-bank",
  "eventType": "transaction",
  "description": "Wire transfer",
  "amount": 1500.00,
  "keyVersion": 1
}
```

Note: `keyVersion` is required to prevent mixing tokens across rotations.

#### List All Users
```http
GET /api/users
```

#### Get User Profile
```http
GET /api/users/{token}
```

#### Link Tokens After Rotation
```http
POST /api/users/link-token
Content-Type: application/json

{
  "oldToken": "hex-encoded-old-token",
  "oldVersion": 1,
  "newToken": "hex-encoded-new-token",
  "newVersion": 2
}
```

#### Get Statistics
```http
GET /api/stats
```

### Key Management Endpoints

#### List All Key Versions
```http
GET /api/keys
```

#### Get Key Version Details
```http
GET /api/keys/{version}
```

#### Rotate Key
```http
POST /api/keys/rotate
```

#### Retire Key Version
```http
DELETE /api/keys/{version}
```

#### Get Key Statistics
```http
GET /api/keys/stats
```

---

## Library Usage

### Basic Server Usage

```java
import com.oprf.OprfServer;
import com.oprf.OprfMode;

// Create a VOPRF server with a new random key
OprfServer server = OprfServer.create(OprfMode.VERIFIABLE);

// Or restore from an existing key
byte[] savedKey = loadKeyFromSecureStorage();
OprfServer server = OprfServer.create(OprfMode.VERIFIABLE, savedKey);

// Evaluate a blinded element from client
byte[] blindedElement = receiveFromClient();
ServerResponse response = server.evaluate(blindedElement);

// Send back to client
sendToClient(response.getEvaluatedElement());  // 33 bytes
sendToClient(response.getProof());              // 64 bytes
```

### Client-Side Token Derivation

```java
import com.oprf.core.*;
import com.oprf.protocol.HashToCurve;

// 1. Hash sensitive data to curve point
GroupElement hashedPoint = HashToCurve.hashToCurve(
    identifier.getBytes(),
    CipherSuite.getHashToCurveDST(OprfMode.VERIFIABLE)
);

// 2. Blind with random scalar
Scalar blind = Scalar.random();
GroupElement blindedElement = hashedPoint.multiply(blind);

// 3. Send to server, get response
byte[] evaluated = callServer(blindedElement.toBytes());

// 4. Unblind
GroupElement evaluatedPoint = GroupElement.fromBytes(evaluated);
GroupElement unblinded = evaluatedPoint.multiply(blind.invert());

// 5. Derive final token
byte[] token = sha256(identifier + unblinded.toBytes());
```

### Key Management

```java
// Generate new server with random key
OprfServer server = OprfServer.create(OprfMode.VERIFIABLE);

// Export for secure storage
byte[] privateKey = server.exportPrivateKey();  // 32 bytes - KEEP SECRET!
byte[] publicKey = server.getPublicKey();       // 33 bytes - share with clients

// Restore later
OprfServer restored = OprfServer.create(OprfMode.VERIFIABLE, privateKey);
```

---

## Technical Details

### Cryptographic Specifications

| Component | Specification |
|-----------|---------------|
| Curve | NIST P-256 (secp256r1) |
| Hash | SHA-256 |
| Hash-to-Curve | RFC 9380 (P256_XMD:SHA-256_SSWU_RO) |
| OPRF Protocol | RFC 9497 |
| Proof System | DLEQ (Discrete Log Equality) |

### Security Properties

| Property | Description |
|----------|-------------|
| **Obliviousness** | Server learns nothing about client's input |
| **Pseudorandomness** | Output is indistinguishable from random without the key |
| **Verifiability** | Client can verify server used the correct key (VOPRF) |
| **Unlinkability** | Server cannot link multiple requests from the same client |
| **Determinism** | Same input + same key = same output (for correlation) |

### Protocol Flow

```
    CLIENT                                 SERVER
       │                                      │
       │  1. H = HashToCurve(input)           │
       │  2. r = random scalar                │
       │  3. B = r × H  (blind)               │
       │                                      │
       │ ─────────── B (blinded) ───────────► │
       │                                      │
       │                    4. Z = k × B  (evaluate)
       │                    5. π = DLEQ_Prove(k, B, Z)
       │                                      │
       │ ◄────────── Z, π (response) ──────── │
       │                                      │
       │  6. Verify π (optional)              │
       │  7. Y = r⁻¹ × Z  (unblind)           │
       │  8. token = Hash(input ‖ Y)          │
       │                                      │
```

---

## Deep Dive: Protocol Security

This section explains each phase of the OPRF protocol with security analysis for those wanting to understand what data is exposed at each step.

### Phase 1: Client Blinding

**What happens:**
```
Client has: identifier = "user-12345"

Step 1: Hash identifier to a curve point
        H = HashToCurve("user-12345")
        → H is a point on the elliptic curve (not reversible to identifier)

Step 2: Generate random blinding factor
        r = random 256-bit number (generated fresh each time)

Step 3: Blind the point
        B = r × H  (scalar multiplication on curve)

Client sends: B (the blinded point, 33 bytes)
```

**Security analysis:**

| Question | Answer |
|----------|--------|
| Does server see identifier? | **No** - identifier was hashed, then blinded |
| Can server reverse B to get identifier? | **No** - would need to know `r`, which is random and never sent |
| Is B deterministic? | **No** - different `r` each time means different `B` each time |
| Can server link two requests for same identifier? | **No** - B is different every time due to random `r` |

**What's actually sent over the wire:**
```
POST /api/oprf/evaluate
{
  "blindedElement": "A3x7k9mN2p..." (base64 of 33 random-looking bytes)
}
```

An attacker intercepting this sees **random-looking bytes** with no connection to the identifier.

### Phase 2: Server Evaluation

**What happens:**
```
Server has: secret key k (256-bit scalar, never shared)
Server receives: B (blinded point)

Step 1: Evaluate
        Z = k × B  (multiply blinded point by secret key)

Step 2: Generate proof (VOPRF only)
        proof = DLEQ_Prove(k, G, PublicKey, B, Z)
        (proves Z was computed correctly without revealing k)

Server returns: Z (evaluated point), proof, PublicKey
```

**Security analysis:**

| Question | Answer |
|----------|--------|
| Does server learn identifier? | **No** - server only sees B, which is blinded |
| Does server learn anything about input? | **No** - B looks random, no information leakage |
| Is the response Z sensitive? | **No** - Z is still blinded (contains factor `r`) |
| Can attacker use Z? | **No** - without `r`, Z is useless |
| What does proof prove? | Server used the correct key (client can verify) |

**What's returned over the wire:**
```json
{
  "evaluatedElement": "Qm4pR8sT1w...",  // 33 bytes, still blinded
  "proof": "x9Yk2mN...",                 // 64 bytes, cryptographic proof
  "publicKey": "A1b2C3..."               // Server's public key
}
```

An attacker intercepting this sees **random-looking bytes**. Without the client's secret `r`, this is useless.

### Phase 3: Client Unblinding & Token Derivation

**What happens:**
```
Client has:
  - Original identifier
  - Blinding factor r (kept secret, never sent)
  - Server response Z = k × B = k × r × H

Step 1: Verify proof (optional but recommended)
        Verify DLEQ proof using server's public key
        → Confirms server used correct key

Step 2: Unblind
        Y = (1/r) × Z
        Y = (1/r) × k × r × H
        Y = k × H  (the r cancels out!)

Step 3: Derive final token
        token = SHA256(identifier || Y)
        → 32-byte deterministic token
```

**Security analysis:**

| Question | Answer |
|----------|--------|
| Can client compute token without server? | **No** - needs `k × H`, only server can compute |
| Is token deterministic? | **Yes** - same identifier always produces same token |
| Can token be reversed to identifier? | **No** - SHA256 is one-way |
| Does token leak identifier? | **No** - token is a hash, looks random |

**The math that makes it work:**
```
Client started with:     H = HashToCurve(identifier)
Client blinded:          B = r × H
Server evaluated:        Z = k × B = k × r × H
Client unblinded:        Y = (1/r) × Z = k × H

The random r completely cancels out!
Result Y depends only on: identifier and server's key k
```

### Phase 4: Onboarding - Token Submission

**What happens:**
```
Client sends to server:
{
  "token": "a1b2c3d4e5f6...",  // 64 hex chars (32 bytes)
  "clientId": "acme-bank",
  "eventType": "onboard",
  "metadata": { ... }
}
```

**Security analysis:**

| Question | Answer |
|----------|--------|
| Does token leak identifier? | **No** - token is `SHA256(identifier \|\| Y)`, not reversible |
| Can server derive identifier from token? | **No** - even with key `k`, would need to brute-force |
| Can two clients correlate same user? | **Yes, by design** - same identifier = same token |

### Summary: What's Sensitive at Each Step

| Data | Sensitive? | Who Has It | Can It Leak Identifier? |
|------|------------|------------|-------------------------|
| Identifier | Yes | Client only | N/A |
| Blinding factor `r` | Temporary | Client only (ephemeral) | No |
| Blinded element `B` | No | Sent to server | No (random-looking) |
| Server key `k` | Yes | Server only | Enables brute-force if leaked |
| Evaluated element `Z` | No | Sent to client | No (still blinded) |
| Unblinded element `Y` | Internal | Client computes | No (but deterministic) |
| Final token | No | Both | No (hash, not reversible) |
| userId | No | Both | No (random UUID) |

**Key insight: Nothing sensitive ever crosses the network.**

---

## Server Data Model

### Recommended Schema (DynamoDB Example)

```
┌─────────────────────────────────────────────────────────────┐
│                    DynamoDB Table: Users                    │
├─────────────────────────────────────────────────────────────┤
│  PK: userId (UUID)          │  GSI: token (derived identifier)
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  {                                                          │
│    "userId": "550e8400-e29b-41d4-a716-446655440000", (PK)   │
│    "token": "a1b2c3d4e5f6...",                       (GSI)  │
│    "createdAt": "2024-01-15T10:30:00Z",                     │
│    "clients": ["acme-bank", "city-hospital"],               │
│    "events": [...]                                          │
│  }                                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Access Patterns

| Operation | How |
|-----------|-----|
| **Onboarding (new user)** | Query GSI by token → not found → create new userId |
| **Onboarding (existing user)** | Query GSI by token → found → return existing userId |
| **Subsequent requests by userId** | Query PK directly (fast) |
| **Subsequent requests by token** | Query GSI → get userId |

### Onboarding Flow

```
┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │  POST /onboard {token: "abc..."}        │
     │────────────────────────────────────────>│
     │                                         │ GSI lookup by token
     │                                         │ Create or find user
     │  {userId: "550e8400...", isNew: true}   │
     │<────────────────────────────────────────│
     │                                         │
     │  POST /events {userId: "550e..."}       │  ← Future calls use userId
     │────────────────────────────────────────>│
     │                                         │ PK lookup (fast)
     │  {success: true}                        │
     │<────────────────────────────────────────│
```

After onboarding, the client can use either:
- **userId** (recommended for performance - direct PK lookup)
- **token** (still works - GSI lookup)

---

## Key Management

### Current Behavior

The server generates a new random key on startup. This is fine for development but **not for production** - restarting the server would generate a new key, making all existing tokens unmatchable.

### Production Recommendations

1. **Store the key securely**
   - Environment variable
   - Encrypted file
   - Secret management service (AWS Secrets Manager, HashiCorp Vault, etc.)

2. **Load key on startup**
   ```java
   byte[] key = loadFromSecureStorage();
   OprfServer server = OprfServer.create(OprfMode.VERIFIABLE, key);
   ```

### Key Versioning

The library includes `OprfKeyManager` for managing multiple key versions during rotation:

```java
import com.oprf.OprfKeyManager;
import com.oprf.OprfMode;

// Create with initial random key (version 1)
OprfKeyManager keyManager = new OprfKeyManager(OprfMode.VERIFIABLE);

// Or restore from existing key
byte[] savedKey = loadFromSecureStorage();
OprfKeyManager keyManager = new OprfKeyManager(OprfMode.VERIFIABLE, savedKey);

// Or restore multiple versions (e.g., after server restart)
Map<Integer, byte[]> versionedKeys = loadAllKeysFromStorage();
OprfKeyManager keyManager = new OprfKeyManager(
    OprfMode.VERIFIABLE,
    versionedKeys,
    currentVersion
);

// Use current server for evaluations
OprfServer server = keyManager.getCurrentServer();
int version = keyManager.getCurrentVersion();

// Rotate to a new key
int newVersion = keyManager.rotateKey();

// Old keys remain available for verification
OprfServer oldServer = keyManager.getServer(oldVersion);

// Export all keys for backup
Map<Integer, byte[]> allKeys = keyManager.exportAllKeys();

// Retire old versions when no longer needed
keyManager.retireVersion(oldVersion);
```

### Key Management REST API

The demo includes REST endpoints for key management:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/keys` | GET | List all key versions |
| `/api/keys/{version}` | GET | Get specific key version info |
| `/api/keys/rotate` | POST | Rotate to a new key version |
| `/api/keys/{version}` | DELETE | Retire an old key version |
| `/api/keys/stats` | GET | Key usage statistics |

Key management endpoints require an admin key header:

```bash
export OPRF_KEY_MANAGEMENT_API_KEY="replace-with-strong-secret"
```

Example responses:

```bash
# List all keys
curl -H "X-Admin-Key: $OPRF_KEY_MANAGEMENT_API_KEY" http://localhost:8080/api/keys
{
  "currentVersion": 2,
  "versions": [
    {"version": 1, "publicKey": "...", "isCurrent": false},
    {"version": 2, "publicKey": "...", "isCurrent": true}
  ],
  "tokensByVersion": {"1": 2, "2": 2}
}

# Rotate to new key
curl -H "X-Admin-Key: $OPRF_KEY_MANAGEMENT_API_KEY" -X POST http://localhost:8080/api/keys/rotate
{
  "previousVersion": 1,
  "newVersion": 2,
  "previousPublicKey": "...",
  "newPublicKey": "...",
  "totalVersions": 2
}

# Key stats
curl -H "X-Admin-Key: $OPRF_KEY_MANAGEMENT_API_KEY" http://localhost:8080/api/keys/stats
{
  "currentKeyVersion": 2,
  "totalKeyVersions": 2,
  "totalUsers": 2,
  "totalEvents": 4,
  "tokensByKeyVersion": {"1": 2, "2": 2}
}
```

### Key Rotation Demo

Run the interactive key rotation demo to see the full workflow:

**Terminal 1 - Start the server:**
```bash
./gradlew :demo:bootRun
```

**Terminal 2 - Run the rotation demo:**
```bash
export OPRF_KEY_MANAGEMENT_API_KEY="replace-with-strong-secret"
./gradlew :demo:rotationDemo
```

The demo shows:

1. **Phase 1:** Derive tokens with key v1, submit events
2. **Phase 2:** Trigger server key rotation to v2
3. **Phase 3:** Derive new tokens (different due to new key)
4. **Phase 4:** Link old tokens to new tokens (token migration)
5. **Phase 5:** Submit events with v2 tokens, verify correlation

Sample output:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 3: Token Derivation After Rotation (Key v2)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Processing: Alice Johnson
  New token: 131bf69396c811d2...
  Key version: 2
  Different from v1 token: ✓ YES
  Old (v1): 3dc5d8510a7ef5a7...
  New (v2): 131bf69396c811d2...
```

### Token Migration (Linking)

When clients upgrade to a new key version, they can link their old token to their new token:

```bash
curl -X POST http://localhost:8080/api/users/link-token \
  -H "Content-Type: application/json" \
  -d '{
    "oldToken": "3dc5d8510a7ef5a7...",
    "oldVersion": 1,
    "newToken": "131bf69396c811d2...",
    "newVersion": 2
  }'
```

This preserves user continuity across key rotations - events from both token versions are correlated to the same user.

### When to Rotate Keys

| Scenario | Action |
|----------|--------|
| Routine (yearly) | Optional - defense in depth |
| Suspected breach | Rotate immediately |
| Employee with key access leaves | Consider rotation |
| Compliance requirement | As required |

### Rotation Strategy

When you need to rotate:

1. Generate new key, increment version
2. New token derivations use new key
3. Existing tokens remain valid (query by version)
4. Clients naturally re-derive on next interaction
5. Server links old token → new token for same user
6. After transition period, retire old key

**Key insight:** Rotation is about limiting future damage, not protecting already-compromised tokens. If a key was compromised, tokens derived with that key are potentially exposed regardless of rotation.

---

## Testing

```bash
# Run all tests
./gradlew test

# Run only core library tests
./gradlew :core:test

# Run with detailed output
./gradlew :core:test --info
```

The test suite includes:
- Unit tests for all cryptographic primitives
- DLEQ proof generation and verification
- Hash-to-curve (RFC 9380) compliance
- Full protocol flow tests
- RFC 9497 test vector validation

---

## License

MIT License

---

## References

- [RFC 9497 - Oblivious Pseudorandom Functions (OPRFs)](https://datatracker.ietf.org/doc/rfc9497/)
- [RFC 9380 - Hashing to Elliptic Curves](https://datatracker.ietf.org/doc/rfc9380/)
- [Bouncy Castle Cryptography Library](https://www.bouncycastle.org/)
