# 🔐 CryptographyLibrary

A minimal, lightweight JWT and encryption class library for .NET. Create and validate **ES256** signed JSON Web Tokens, with optional **post-quantum** and **elliptic curve** encryption for sensitive payload sections.

---

## ✨ Features

- **ES256 JWT Signing** — ECDSA with P-256 curve for compact, secure signatures
- **Simple JWT API** — Just `Create()` and `Verify()` methods
- **Verify-Only Mode** — Distribute public keys safely for token verification
- **Post-Quantum Encryption** — ML-KEM (FIPS 203) + AES for quantum-resistant confidentiality
- **Elliptic Curve Encryption** — ECDH + AES using the ECIES pattern
- **Selective Encryption** — Encrypt sensitive payload sections for specific recipients
- **Zero Dependencies** — Built entirely on .NET's native cryptography libraries

---

## 🚀 Quick Start

### JWT Signing & Verification
```csharp
// Create tokens with auto-generated keys
var issuer = new JwtES256();

// Sign a token
string token = issuer.Create("{\"sub\":\"user123\",\"role\":\"admin\"}");

// Verify and extract payload
if (issuer.Verify(token, out string payload))
{
    Console.WriteLine($"Valid! Payload: {payload}");
}

// Export keys for distribution
string publicKeyPem = issuer.ExportPublicKeyPem();

// Create a verify-only instance (for third parties)
var verifier = JwtES256.CreateVerifier(publicKeyPem);
bool isValid = verifier.Verify(token, out payload);
```

### Encrypting Sensitive Data (Elliptic Curve)
```csharp
// Recipient generates their key pair
using var recipient = new EncryptorEcdh();
string publicKey = recipient.ExportPublicKeyPem();

// Sender encrypts using recipient's public key only
string encrypted = EncryptorEcdh.Encrypt("sensitive data", publicKey);

// Only recipient can decrypt with their private key
string decrypted = recipient.Decrypt(encrypted);
```

### Post-Quantum Encryption (ML-KEM)
```csharp
// Recipient generates ML-KEM key pair
using var recipient = new EncryptorMLKem(MLKemAlgorithm.MLKem768);
string publicKey = recipient.ExportPublicKeyPem();

// Sender encrypts (quantum-resistant)
string encrypted = EncryptorMLKem.Encrypt("sensitive data", publicKey);

// Only recipient can decrypt
string decrypted = recipient.Decrypt(encrypted);
```

---

## 📦 Installation
```bash
dotnet add package CryptographyLibrary
```

> **Note:** ML-KEM requires .NET 10+ with platform support (Windows CNG with PQC or Linux with OpenSSL 3.5+)

---

## 🔧 Usage

### JwtES256 — Token Signing
```csharp
// Generate new key pair
var jwt = new JwtES256();

// Or use existing keys
var jwt = new JwtES256(privateKeyPem, publicKeyPem);

// Or create verify-only instance
var verifier = JwtES256.CreateVerifier(publicKeyPem);

// Create token
string token = jwt.Create("{\"sub\":\"123\",\"exp\":1699999999}");

// Verify token
if (jwt.Verify(token, out string payload))
{
    // Token is valid, payload contains the data
}

// Export keys
string privateKey = jwt.ExportPrivateKeyPem();
string publicKey = jwt.ExportPublicKeyPem();
```

### EncryptorEcdh — Elliptic Curve Encryption
```csharp
// Generate new key pair
using var encryptor = new EncryptorEcdh();

// Or import existing private key
using var encryptor = new EncryptorEcdh(privateKeyPem);

// Encrypt (static method - only needs recipient's public key)
string encrypted = EncryptorEcdh.Encrypt(plaintext, recipientPublicKeyPem);
byte[] encryptedBytes = EncryptorEcdh.EncryptBytes(data, recipientPublicKeyPem);

// Decrypt (instance method - needs private key)
string decrypted = encryptor.Decrypt(encrypted);
byte[] decryptedBytes = encryptor.DecryptBytes(encryptedBytes);

// Export keys
string privateKey = encryptor.ExportPrivateKeyPem();
string publicKey = encryptor.ExportPublicKeyPem();
```

### EncryptorMLKem — Post-Quantum Encryption
```csharp
// Generate with default algorithm (ML-KEM-768)
using var encryptor = new EncryptorMLKem();

// Or specify security level
using var encryptor = new EncryptorMLKem(MLKemAlgorithm.MLKem512);  // 128-bit
using var encryptor = new EncryptorMLKem(MLKemAlgorithm.MLKem768);  // 192-bit
using var encryptor = new EncryptorMLKem(MLKemAlgorithm.MLKem1024); // 256-bit

// Or import existing private key
using var encryptor = new EncryptorMLKem(privateKeyPem);

// Encrypt/Decrypt (same API as EncryptorEcdh)
string encrypted = EncryptorMLKem.Encrypt(plaintext, recipientPublicKeyPem);
string decrypted = encryptor.Decrypt(encrypted);
```

---

## 🏗️ Architecture: JWT with Encrypted Sections

A common pattern is to have JWTs where some payload sections are encrypted for specific recipients:
```
┌─────────────────────────────────────────────────────────────────┐
│                      JWT TOKEN                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Header: { "alg": "ES256", "typ": "JWT" }                  │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │ Payload: {                                                │  │
│  │   "sub": "user-123",               ← Public (anyone)      │  │
│  │   "name": "Alice",                 ← Public (anyone)      │  │
│  │   "exp": 1699999999,               ← Public (anyone)      │  │
│  │   "encryptedData": "base64..."     ← Private (owner only) │  │
│  │ }                                                         │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │ Signature (ES256)                  ← Verifiable by anyone │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Complete Example: Financial Service
```csharp
// === SETUP ===

// Issuer (service) has signing keys
var issuer = new JwtES256();
var issuerPublicKey = issuer.ExportPublicKeyPem();

// Each user has their own encryption keys
using var alice = new EncryptorEcdh();
using var bob = new EncryptorEcdh();

// === ISSUER CREATES TOKENS ===

var aliceAccountData = new {
    balance = 1500.00,
    lockedBalance = 200.00,
    limits = new {
        transactionsPerDay = 10,
        amountPerDay = 2000
    }
};

// Encrypt sensitive data for Alice using HER public key
var encryptedForAlice = EncryptorEcdh.Encrypt(
    JsonSerializer.Serialize(aliceAccountData),
    alice.ExportPublicKeyPem()
);

// Create and sign the token
var tokenPayload = new {
    sub = "alice",
    name = "Alice Smith",
    exp = DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds(),
    encryptedData = encryptedForAlice
};

var aliceToken = issuer.Create(JsonSerializer.Serialize(tokenPayload));

// === VERIFICATION (by any service) ===

var verifier = JwtES256.CreateVerifier(issuerPublicKey);

if (verifier.Verify(aliceToken, out var payload))
{
    var parsed = JsonSerializer.Deserialize<TokenPayload>(payload);
    Console.WriteLine($"Token for: {parsed.Name}");  // Anyone can see this
    
    // But only Alice can decrypt:
    var accountData = alice.Decrypt(parsed.EncryptedData);
}

// === SECURITY ===

// Bob CANNOT decrypt Alice's data
Assert.Throws<CryptographicException>(() => 
    bob.Decrypt(encryptedForAlice)
);
```

---

## 🛡️ Security

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| JWT Signing | ES256 (ECDSA P-256 + SHA-256) | 128-bit classical |
| ECDH Encryption | ECDH P-256 + AES-256-CBC | 128-bit classical |
| ML-KEM-512 | FIPS 203 + AES-256-CBC | 128-bit post-quantum |
| ML-KEM-768 | FIPS 203 + AES-256-CBC | 192-bit post-quantum |
| ML-KEM-1024 | FIPS 203 + AES-256-CBC | 256-bit post-quantum |

### When to Use What?

| Scenario | Recommendation |
|----------|----------------|
| Standard applications | `EncryptorEcdh` — widely supported, smaller keys |
| Long-term secrets (10+ years) | `EncryptorMLKem` — quantum-resistant |
| Regulatory requirements (PQC) | `EncryptorMLKem` — NIST FIPS 203 compliant |
| Constrained environments | `EncryptorEcdh` — smaller ciphertext overhead |

### Encrypted Output Formats

**EncryptorEcdh:**
```
[4 bytes: key length][ephemeral public key][16 bytes: IV][AES ciphertext]
```

**EncryptorMLKem:**
```
[ML-KEM ciphertext (768-1568 bytes)][16 bytes: IV][AES ciphertext]
```

---

## 🧪 Testing
```bash
dotnet test
```

The test suite includes:

- **JwtES256Tests** — Token creation, verification, tampering detection
- **EncryptorEcdhTests** — Encryption round-trips, key management, security
- **EncryptorMLKemTests** — All ML-KEM variants, quantum-resistant encryption
- **JwtWithEncryptedPayloadTests** — Integration tests with multi-actor scenarios

---

## 📋 API Reference

### JwtES256

| Method | Description |
|--------|-------------|
| `JwtES256()` | Create with auto-generated keys |
| `JwtES256(privateKeyPem, publicKeyPem)` | Create with existing keys |
| `JwtES256.CreateVerifier(publicKeyPem)` | Create verify-only instance |
| `Create(payload)` | Sign payload and return JWT string |
| `Verify(token, out payload)` | Verify signature and extract payload |
| `ExportPrivateKeyPem()` | Export private key as PEM |
| `ExportPublicKeyPem()` | Export public key as PEM |

### EncryptorEcdh

| Method | Description |
|--------|-------------|
| `EncryptorEcdh()` | Create with auto-generated P-256 keys |
| `EncryptorEcdh(privateKeyPem)` | Create from existing private key |
| `Encrypt(plaintext, publicKeyPem)` | Static: encrypt string for recipient |
| `EncryptBytes(data, publicKeyPem)` | Static: encrypt bytes for recipient |
| `Decrypt(encrypted)` | Decrypt string using private key |
| `DecryptBytes(encrypted)` | Decrypt bytes using private key |
| `ExportPrivateKeyPem()` | Export private key as PEM |
| `ExportPublicKeyPem()` | Export public key as PEM |

### EncryptorMLKem

| Method | Description |
|--------|-------------|
| `EncryptorMLKem()` | Create with ML-KEM-768 (default) |
| `EncryptorMLKem(algorithm)` | Create with specified algorithm |
| `EncryptorMLKem(privateKeyPem)` | Create from existing private key |
| `Encrypt(plaintext, publicKeyPem)` | Static: encrypt string for recipient |
| `EncryptBytes(data, publicKeyPem)` | Static: encrypt bytes for recipient |
| `Decrypt(encrypted)` | Decrypt string using private key |
| `DecryptBytes(encrypted)` | Decrypt bytes using private key |
| `Algorithm` | Get the ML-KEM algorithm in use |
| `ExportPrivateKeyPem()` | Export private key as PEM |
| `ExportPublicKeyPem()` | Export public key as PEM |

---

## 📄 License

MIT

---

<p align="center">
  Made with ❤️ using <b>.NET 10</b>
</p>