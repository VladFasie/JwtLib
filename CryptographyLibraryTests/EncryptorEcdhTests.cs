using System.Security.Cryptography;
using CryptographyLibrary;
using System.Text;

namespace CryptographyLibraryTests;

public class EncryptorEcdhTests
{
    [Fact]
    public void Encrypt_Decrypt_RoundTrip_ReturnsOriginalString()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Hello, elliptic curve world!";
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesDifferentOutputEachTime()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Same message";
        var encrypted1 = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
        var encrypted2 = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);

        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        using var recipient1 = new EncryptorEcdh();
        using var recipient2 = new EncryptorEcdh();
        var publicKeyPem = recipient1.ExportPublicKeyPem();

        var plaintext = "Secret message";
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);

        Assert.ThrowsAny<CryptographicException>(() => recipient2.Decrypt(encrypted));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_Fails()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Secret message";
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
        var encryptedBytes = Convert.FromBase64String(encrypted);

        // Tamper with the encrypted data portion (at the end)
        encryptedBytes[encryptedBytes.Length - 1] ^= 0xFF;
        var tamperedEncrypted = Convert.ToBase64String(encryptedBytes);

        Assert.ThrowsAny<CryptographicException>(() => recipient.Decrypt(tamperedEncrypted));
    }

    [Fact]
    public void Decrypt_WithTamperedEphemeralKey_Fails()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Secret message";
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
        var encryptedBytes = Convert.FromBase64String(encrypted);

        // Tamper with the ephemeral public key (after length prefix)
        encryptedBytes[10] ^= 0xFF;
        var tamperedEncrypted = Convert.ToBase64String(encryptedBytes);

        Assert.ThrowsAny<CryptographicException>(() => recipient.Decrypt(tamperedEncrypted));
    }

    [Fact]
    public void Decrypt_WithInvalidBase64_Fails()
    {
        using var recipient = new EncryptorEcdh();

        Assert.ThrowsAny<FormatException>(() => recipient.Decrypt("not-valid-base64!!!"));
    }

    [Fact]
    public void Decrypt_WithTooShortData_Fails()
    {
        using var recipient = new EncryptorEcdh();
        var shortData = Convert.ToBase64String(new byte[3]);

        Assert.Throws<CryptographicException>(() => recipient.Decrypt(shortData));
    }

    [Fact]
    public void Encrypt_Decrypt_WithEmptyString_Works()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "";
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithUnicodeCharacters_Works()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Hello, 世界! 🔐🌍 Привет мир! مرحبا";
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithLargePayload_Works()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = new string('x', 100_000);
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithJsonPayload_Works()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "{\"ssn\":\"123-45-6789\",\"credit_card\":\"4111-1111-1111-1111\"}";
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptBytes_DecryptBytes_RoundTrip_Works()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = new byte[] { 0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD };
        var encrypted = EncryptorEcdh.EncryptBytes(plaintext, publicKeyPem);
        var decrypted = recipient.DecryptBytes(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void ExportPrivateKeyPem_ReturnsValidPem()
    {
        using var encryptor = new EncryptorEcdh();

        var pem = encryptor.ExportPrivateKeyPem();

        Assert.Contains("-----BEGIN EC PRIVATE KEY-----", pem);
        Assert.Contains("-----END EC PRIVATE KEY-----", pem);
    }

    [Fact]
    public void ExportPublicKeyPem_ReturnsValidPem()
    {
        using var encryptor = new EncryptorEcdh();

        var pem = encryptor.ExportPublicKeyPem();

        Assert.Contains("-----BEGIN PUBLIC KEY-----", pem);
        Assert.Contains("-----END PUBLIC KEY-----", pem);
    }

    [Fact]
    public void Constructor_WithPrivateKeyPem_CanDecrypt()
    {
        using var original = new EncryptorEcdh();
        var privateKeyPem = original.ExportPrivateKeyPem();
        var publicKeyPem = original.ExportPublicKeyPem();

        var plaintext = "Test message";
        var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);

        using var restored = new EncryptorEcdh(privateKeyPem);
        var decrypted = restored.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void MultipleEncryptDecrypt_SameInstance_Works()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        for (int i = 0; i < 10; i++)
        {
            var plaintext = $"Message number {i}";
            var encrypted = EncryptorEcdh.Encrypt(plaintext, publicKeyPem);
            var decrypted = recipient.Decrypt(encrypted);
            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public void Encrypt_Decrypt_BinaryDataWithNullBytes_Works()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = new byte[] { 0x00, 0x00, 0x00, 0x01, 0x00, 0x02 };
        var encrypted = EncryptorEcdh.EncryptBytes(plaintext, publicKeyPem);
        var decrypted = recipient.DecryptBytes(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void DifferentRecipients_CannotDecryptEachOthersMessages()
    {
        using var alice = new EncryptorEcdh();
        using var bob = new EncryptorEcdh();

        var messageForAlice = EncryptorEcdh.Encrypt("For Alice only", alice.ExportPublicKeyPem());
        var messageForBob = EncryptorEcdh.Encrypt("For Bob only", bob.ExportPublicKeyPem());

        // Each can decrypt their own
        Assert.Equal("For Alice only", alice.Decrypt(messageForAlice));
        Assert.Equal("For Bob only", bob.Decrypt(messageForBob));

        // But not each other's
        Assert.ThrowsAny<CryptographicException>(() => alice.Decrypt(messageForBob));
        Assert.ThrowsAny<CryptographicException>(() => bob.Decrypt(messageForAlice));
    }

    [Fact]
    public void EncryptedOutput_ContainsExpectedComponents()
    {
        using var recipient = new EncryptorEcdh();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Test";
        var encryptedBytes = EncryptorEcdh.EncryptBytes(Encoding.UTF8.GetBytes(plaintext), publicKeyPem);

        // Should have: 4 bytes length + ephemeral key (~91 bytes for P-256) + 16 bytes IV + encrypted data
        Assert.True(encryptedBytes.Length > 4 + 16 + 1);

        // Extract and verify ephemeral key length is reasonable for P-256
        var keyLength = BitConverter.ToInt32(encryptedBytes.AsSpan(0, 4));
        Assert.InRange(keyLength, 85, 100); // P-256 SubjectPublicKeyInfo is typically ~91 bytes
    }
}
