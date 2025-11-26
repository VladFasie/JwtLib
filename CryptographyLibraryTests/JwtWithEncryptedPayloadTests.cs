using System.Security.Cryptography;
using System.Text.Json;
using CryptographyLibrary;

namespace CryptographyLibraryTests;

public class JwtWithEncryptedPayloadTests
{
    // Models for the payload
    public class Limits
    {
        public int TransactionsPerDay { get; set; }
        public int TransactionsPerMonth { get; set; }
        public decimal AmountPerTransaction { get; set; }
        public decimal AmountPerDay { get; set; }
        public decimal AmountPerMonth { get; set; }
    }

    public class SensitivePayload
    {
        public decimal Balance { get; set; }
        public decimal LockedBalance { get; set; }
        public Limits Limits { get; set; }
    }

    public class TokenPayload
    {
        public string Sub { get; set; }
        public string Name { get; set; }
        public long Iat { get; set; }
        public long Exp { get; set; }
        public string EncryptedData { get; set; }
    }

    [Fact]
    public void Issuer_CreatesTokens_AnyoneCanVerify_OnlyOwnerCanDecrypt()
    {
        // ============================================================
        // SETUP: Create actors and their keys
        // ============================================================

        // Issuer has ES256 key pair for signing JWTs
        var issuer = new JwtEs256();
        var issuerPublicKeyPem = issuer.ExportPublicKeyPem();

        // User A has ECDH key pair for encryption
        using var userA = new EncryptorEcdh();
        var userAPublicKeyPem = userA.ExportPublicKeyPem();

        // User B has ECDH key pair for encryption
        using var userB = new EncryptorEcdh();
        var userBPublicKeyPem = userB.ExportPublicKeyPem();

        // A third party (verifier) who only has issuer's public key
        var verifier = new JwtEs256(issuer.ExportPrivateKeyPem(), issuerPublicKeyPem);

        // ============================================================
        // ISSUER: Create sensitive payloads for each user
        // ============================================================

        var sensitivePayloadA = new SensitivePayload
        {
            Balance = 120.05m,
            LockedBalance = 24.79m,
            Limits = new Limits
            {
                TransactionsPerDay = 5,
                TransactionsPerMonth = 50,
                AmountPerTransaction = 100,
                AmountPerDay = 1000,
                AmountPerMonth = 5000
            }
        };

        var sensitivePayloadB = new SensitivePayload
        {
            Balance = 999.99m,
            LockedBalance = 100.00m,
            Limits = new Limits
            {
                TransactionsPerDay = 10,
                TransactionsPerMonth = 100,
                AmountPerTransaction = 500,
                AmountPerDay = 2000,
                AmountPerMonth = 10000
            }
        };

        // ============================================================
        // ISSUER: Encrypt sensitive data for each user using THEIR public keys
        // ============================================================

        var encryptedDataA = EncryptorEcdh.Encrypt(
            JsonSerializer.Serialize(sensitivePayloadA),
            userAPublicKeyPem
        );

        var encryptedDataB = EncryptorEcdh.Encrypt(
            JsonSerializer.Serialize(sensitivePayloadB),
            userBPublicKeyPem
        );

        // ============================================================
        // ISSUER: Create and sign JWTs for each user
        // ============================================================

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var expiry = now + 3600; // 1 hour

        var tokenPayloadA = new TokenPayload
        {
            Sub = "user-a-123",
            Name = "Alice",
            Iat = now,
            Exp = expiry,
            EncryptedData = encryptedDataA
        };

        var tokenPayloadB = new TokenPayload
        {
            Sub = "user-b-456",
            Name = "Bob",
            Iat = now,
            Exp = expiry,
            EncryptedData = encryptedDataB
        };

        var tokenA = issuer.Create(JsonSerializer.Serialize(tokenPayloadA));
        var tokenB = issuer.Create(JsonSerializer.Serialize(tokenPayloadB));

        // ============================================================
        // TEST 1: Anyone with issuer's public key can verify both tokens
        // ============================================================

        Assert.True(verifier.Verify(tokenA, out var verifiedPayloadA));
        Assert.True(verifier.Verify(tokenB, out var verifiedPayloadB));

        // Verify the non-encrypted parts are accessible
        var parsedPayloadA = JsonSerializer.Deserialize<TokenPayload>(verifiedPayloadA);
        var parsedPayloadB = JsonSerializer.Deserialize<TokenPayload>(verifiedPayloadB);

        Assert.Equal("user-a-123", parsedPayloadA.Sub);
        Assert.Equal("Alice", parsedPayloadA.Name);
        Assert.Equal("user-b-456", parsedPayloadB.Sub);
        Assert.Equal("Bob", parsedPayloadB.Name);

        // ============================================================
        // TEST 2: User A can decrypt their own encrypted data
        // ============================================================

        var decryptedJsonA = userA.Decrypt(parsedPayloadA.EncryptedData);
        var decryptedPayloadA = JsonSerializer.Deserialize<SensitivePayload>(decryptedJsonA);

        Assert.Equal(120.05m, decryptedPayloadA.Balance);
        Assert.Equal(24.79m, decryptedPayloadA.LockedBalance);
        Assert.Equal(5, decryptedPayloadA.Limits.TransactionsPerDay);
        Assert.Equal(50, decryptedPayloadA.Limits.TransactionsPerMonth);
        Assert.Equal(100, decryptedPayloadA.Limits.AmountPerTransaction);
        Assert.Equal(1000, decryptedPayloadA.Limits.AmountPerDay);
        Assert.Equal(5000, decryptedPayloadA.Limits.AmountPerMonth);

        // ============================================================
        // TEST 3: User B can decrypt their own encrypted data
        // ============================================================

        var decryptedJsonB = userB.Decrypt(parsedPayloadB.EncryptedData);
        var decryptedPayloadB = JsonSerializer.Deserialize<SensitivePayload>(decryptedJsonB);

        Assert.Equal(999.99m, decryptedPayloadB.Balance);
        Assert.Equal(100.00m, decryptedPayloadB.LockedBalance);
        Assert.Equal(10, decryptedPayloadB.Limits.TransactionsPerDay);
        Assert.Equal(100, decryptedPayloadB.Limits.TransactionsPerMonth);
        Assert.Equal(500, decryptedPayloadB.Limits.AmountPerTransaction);
        Assert.Equal(2000, decryptedPayloadB.Limits.AmountPerDay);
        Assert.Equal(10000, decryptedPayloadB.Limits.AmountPerMonth);

        // ============================================================
        // TEST 4: User A CANNOT decrypt User B's encrypted data
        // ============================================================

        Assert.ThrowsAny<CryptographicException>(() =>
            userA.Decrypt(parsedPayloadB.EncryptedData)
        );

        // ============================================================
        // TEST 5: User B CANNOT decrypt User A's encrypted data
        // ============================================================

        Assert.ThrowsAny<CryptographicException>(() =>
            userB.Decrypt(parsedPayloadA.EncryptedData)
        );

        // ============================================================
        // TEST 6: Tampered token fails verification
        // ============================================================

        var tamperedToken = tokenA.Substring(0, tokenA.Length - 5) + "XXXXX";
        Assert.False(verifier.Verify(tamperedToken, out _));

        // ============================================================
        // TEST 7: Token signed by different issuer fails verification
        // ============================================================

        var fakeIssuer = new JwtEs256();
        var fakeToken = fakeIssuer.Create(JsonSerializer.Serialize(tokenPayloadA));
        Assert.False(verifier.Verify(fakeToken, out _));
    }

    [Fact]
    public void ThirdParty_CanVerifyToken_ButCannotDecryptSensitiveData()
    {
        // Setup
        var issuer = new JwtEs256();
        using var user = new EncryptorEcdh();
        using var thirdParty = new EncryptorEcdh(); // Third party has their own keys

        // Create a verifier with only issuer's public key
        var verifierOnlyPublic = new JwtEs256(issuer.ExportPrivateKeyPem(), issuer.ExportPublicKeyPem());

        // Issuer creates token with encrypted data for user
        var sensitiveData = new SensitivePayload
        {
            Balance = 500.00m,
            LockedBalance = 50.00m,
            Limits = new Limits
            {
                TransactionsPerDay = 3,
                TransactionsPerMonth = 30,
                AmountPerTransaction = 200,
                AmountPerDay = 500,
                AmountPerMonth = 2000
            }
        };

        var encryptedData = EncryptorEcdh.Encrypt(
            JsonSerializer.Serialize(sensitiveData),
            user.ExportPublicKeyPem()
        );

        var tokenPayload = new TokenPayload
        {
            Sub = "user-123",
            Name = "Test User",
            Iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            EncryptedData = encryptedData
        };

        var token = issuer.Create(JsonSerializer.Serialize(tokenPayload));

        // Third party CAN verify the token
        Assert.True(verifierOnlyPublic.Verify(token, out var payload));

        var parsed = JsonSerializer.Deserialize<TokenPayload>(payload);
        Assert.Equal("user-123", parsed.Sub);
        Assert.Equal("Test User", parsed.Name);

        // Third party can SEE the encrypted data exists
        Assert.NotNull(parsed.EncryptedData);
        Assert.NotEmpty(parsed.EncryptedData);

        // Third party CANNOT decrypt the sensitive data
        Assert.ThrowsAny<CryptographicException>(() =>
            thirdParty.Decrypt(parsed.EncryptedData)
        );

        // But the actual user CAN decrypt it
        var decrypted = user.Decrypt(parsed.EncryptedData);
        var decryptedPayload = JsonSerializer.Deserialize<SensitivePayload>(decrypted);
        Assert.Equal(500.00m, decryptedPayload.Balance);
    }

    [Fact]
    public void MultipleTokens_SameUser_EachHasUniqueEncryption()
    {
        var issuer = new JwtEs256();
        using var user = new EncryptorEcdh();

        var sensitiveData = new SensitivePayload
        {
            Balance = 100.00m,
            LockedBalance = 10.00m,
            Limits = new Limits
            {
                TransactionsPerDay = 1,
                TransactionsPerMonth = 10,
                AmountPerTransaction = 50,
                AmountPerDay = 100,
                AmountPerMonth = 500
            }
        };

        var sensitiveJson = JsonSerializer.Serialize(sensitiveData);

        // Create two tokens with same data
        var encrypted1 = EncryptorEcdh.Encrypt(sensitiveJson, user.ExportPublicKeyPem());
        var encrypted2 = EncryptorEcdh.Encrypt(sensitiveJson, user.ExportPublicKeyPem());

        // Encrypted values should be different (due to ephemeral keys)
        Assert.NotEqual(encrypted1, encrypted2);

        // But both decrypt to the same value
        Assert.Equal(sensitiveJson, user.Decrypt(encrypted1));
        Assert.Equal(sensitiveJson, user.Decrypt(encrypted2));
    }

    [Fact]
    public void CompleteWorkflow_IssuerRegistersUsers_CreatesTokens_UsersAccessOwnData()
    {
        // ============================================================
        // SCENARIO: A financial service issuing account tokens
        // ============================================================

        // 1. Service (Issuer) initialization
        var issuer = new JwtEs256();
        var issuerPublicKey = issuer.ExportPublicKeyPem();

        // 2. User registration - each user generates their key pair
        //    and shares their public key with the issuer
        using var alice = new EncryptorEcdh();
        using var bob = new EncryptorEcdh();

        var alicePublicKey = alice.ExportPublicKeyPem();
        var bobPublicKey = bob.ExportPublicKeyPem();

        // 3. Issuer stores user public keys (simulated as a dictionary)
        var userPublicKeys = new Dictionary<string, string>
        {
            { "alice", alicePublicKey },
            { "bob", bobPublicKey }
        };

        // 4. Issuer creates personalized tokens with encrypted account data
        string CreateAccountToken(string userId, string userName, SensitivePayload accountData)
        {
            var encrypted = EncryptorEcdh.Encrypt(
                JsonSerializer.Serialize(accountData),
                userPublicKeys[userId]
            );

            var payload = new TokenPayload
            {
                Sub = userId,
                Name = userName,
                Iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Exp = DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeSeconds(),
                EncryptedData = encrypted
            };

            return issuer.Create(JsonSerializer.Serialize(payload));
        }

        var aliceToken = CreateAccountToken("alice", "Alice Smith", new SensitivePayload
        {
            Balance = 1500.00m,
            LockedBalance = 200.00m,
            Limits = new Limits
            {
                TransactionsPerDay = 10,
                TransactionsPerMonth = 100,
                AmountPerTransaction = 500,
                AmountPerDay = 2000,
                AmountPerMonth = 15000
            }
        });

        var bobToken = CreateAccountToken("bob", "Bob Jones", new SensitivePayload
        {
            Balance = 250.50m,
            LockedBalance = 0.00m,
            Limits = new Limits
            {
                TransactionsPerDay = 3,
                TransactionsPerMonth = 20,
                AmountPerTransaction = 100,
                AmountPerDay = 300,
                AmountPerMonth = 1000
            }
        });

        // 5. Any service can verify tokens with issuer's public key
        var verifier = new JwtEs256(issuer.ExportPrivateKeyPem(), issuerPublicKey);

        Assert.True(verifier.Verify(aliceToken, out var alicePayloadJson));
        Assert.True(verifier.Verify(bobToken, out var bobPayloadJson));

        // 6. Alice accesses her token
        var alicePayload = JsonSerializer.Deserialize<TokenPayload>(alicePayloadJson);
        Assert.Equal("alice", alicePayload.Sub);
        Assert.Equal("Alice Smith", alicePayload.Name);

        var aliceAccountData = JsonSerializer.Deserialize<SensitivePayload>(
            alice.Decrypt(alicePayload.EncryptedData)
        );
        Assert.Equal(1500.00m, aliceAccountData.Balance);
        Assert.Equal(200.00m, aliceAccountData.LockedBalance);
        Assert.Equal(10, aliceAccountData.Limits.TransactionsPerDay);

        // 7. Bob accesses his token
        var bobPayload = JsonSerializer.Deserialize<TokenPayload>(bobPayloadJson);
        Assert.Equal("bob", bobPayload.Sub);
        Assert.Equal("Bob Jones", bobPayload.Name);

        var bobAccountData = JsonSerializer.Deserialize<SensitivePayload>(
            bob.Decrypt(bobPayload.EncryptedData)
        );
        Assert.Equal(250.50m, bobAccountData.Balance);
        Assert.Equal(0.00m, bobAccountData.LockedBalance);
        Assert.Equal(3, bobAccountData.Limits.TransactionsPerDay);

        // 8. Cross-access attempts fail
        Assert.ThrowsAny<CryptographicException>(() =>
            alice.Decrypt(bobPayload.EncryptedData)
        );
        Assert.ThrowsAny<CryptographicException>(() =>
            bob.Decrypt(alicePayload.EncryptedData)
        );

        // 9. External attacker cannot decrypt either
        using var attacker = new EncryptorEcdh();
        Assert.ThrowsAny<CryptographicException>(() =>
            attacker.Decrypt(alicePayload.EncryptedData)
        );
        Assert.ThrowsAny<CryptographicException>(() =>
            attacker.Decrypt(bobPayload.EncryptedData)
        );
    }
}
