# 🔐 JwtLib

A minimal, lightweight JWT class library for .NET. Create and validate **ES256** signed JSON Web Tokens with ease.

---

## ✨ Features

- **ES256 Signing** — Uses elliptic curve cryptography (NIST P-256) for compact, secure signatures
- **Simple API** — Just two methods: `Create()` and `Verify()`
- **Key Management** — Auto-generate keys or bring your own PEM-formatted keys
- **Third-Party Encryption** — Supports encrypting a portion of the payload for secure data sharing with external parties
- **Zero Dependencies** — Built entirely on .NET's native cryptography libraries

---

## 🚀 Quick Start
```csharp
// Initialize with auto-generated keys
var jwt = new JwtES256();

// Create a token
string token = jwt.Create("{\"sub\":\"user123\",\"role\":\"admin\"}");

// Verify and extract payload
if (jwt.Verify(token, out string payload))
{
    Console.WriteLine($"Valid token! Payload: {payload}");
}
```

---

## 📦 Installation
```bash
dotnet add package JwtLib
```

---

## 🔧 Usage

### Creating Tokens
```csharp
var jwt = new JwtES256();
string token = jwt.Create("{\"userId\":\"12345\",\"exp\":1699999999}");
```

### Verifying Tokens
```csharp
if (jwt.Verify(token, out string payload))
{
    // Token is valid, payload contains the decrypted data
}
else
{
    // Invalid signature or malformed token
}
```

### Using Existing Keys
```csharp
var jwt = new JwtES256(privateKeyPem, publicKeyPem);
```

### Exporting Keys
```csharp
string privateKey = jwt.ExportPrivateKeyPem();
string publicKey = jwt.ExportPublicKeyPem();
```

---

## 🛡️ Security

JwtLib uses the **ES256** algorithm (ECDSA with P-256 curve and SHA-256), which provides strong security with smaller key sizes compared to RSA. This makes it ideal for mobile and IoT applications where bandwidth and storage are constrained.

---

## 📄 License

MIT

---

<p align="center">
  Made with ❤️ using <b>.NET 10</b>
</p>