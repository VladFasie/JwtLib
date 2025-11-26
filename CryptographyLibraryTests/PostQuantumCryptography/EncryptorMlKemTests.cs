using System.Security.Cryptography;
using CryptographyLibrary.PostQuantumCryptography;

namespace CryptographyLibraryTests.PostQuantumCryptography;

#pragma warning disable SYSLIB5006 // ML-KEM is experimental in .NET 10

public class EncryptorMlKemTests
{
    [Fact]
    public void Encrypt_Decrypt_RoundTrip_ReturnsOriginalString()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();
        
        var plaintext = "Hello, post-quantum world!";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithMLKem512_Works()
    {
        using var recipient = new EncryptorMlKem(MLKemAlgorithm.MLKem512);
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Testing ML-KEM-512";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithMLKem768_Works()
    {
        using var recipient = new EncryptorMlKem(MLKemAlgorithm.MLKem768);
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Testing ML-KEM-768";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithMLKem1024_Works()
    {
        using var recipient = new EncryptorMlKem(MLKemAlgorithm.MLKem1024);
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Testing ML-KEM-1024";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesDifferentOutputEachTime()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Same message";
        var encrypted1 = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var encrypted2 = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);

        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void Decrypt_WithWrongKey_Fails()
    {
        using var recipient1 = new EncryptorMlKem();
        using var recipient2 = new EncryptorMlKem();
        var publicKeyPem = recipient1.ExportPublicKeyPem();

        var plaintext = "Secret message";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);

        Assert.ThrowsAny<CryptographicException>(() => recipient2.Decrypt(encrypted));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_Fails()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Secret message";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var encryptedBytes = Convert.FromBase64String(encrypted);
        
        // Tamper with the encrypted data portion (after ciphertext and IV)
        encryptedBytes[encryptedBytes.Length - 1] ^= 0xFF;
        var tamperedEncrypted = Convert.ToBase64String(encryptedBytes);

        Assert.ThrowsAny<CryptographicException>(() => recipient.Decrypt(tamperedEncrypted));
    }

    [Fact]
    public void Decrypt_WithTamperedKemCiphertext_Fails()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Secret message";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var encryptedBytes = Convert.FromBase64String(encrypted);
        
        // Tamper with the KEM ciphertext portion (at the beginning)
        encryptedBytes[0] ^= 0xFF;
        var tamperedEncrypted = Convert.ToBase64String(encryptedBytes);

        Assert.ThrowsAny<CryptographicException>(() => recipient.Decrypt(tamperedEncrypted));
    }

    [Fact]
    public void Decrypt_WithInvalidBase64_Fails()
    {
        using var recipient = new EncryptorMlKem();

        Assert.ThrowsAny<FormatException>(() => recipient.Decrypt("not-valid-base64!!!"));
    }

    [Fact]
    public void Decrypt_WithTooShortData_Fails()
    {
        using var recipient = new EncryptorMlKem();
        var shortData = Convert.ToBase64String(new byte[10]);

        Assert.Throws<CryptographicException>(() => recipient.Decrypt(shortData));
    }

    [Fact]
    public void Encrypt_Decrypt_WithEmptyString_Works()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithUnicodeCharacters_Works()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "Hello, 世界! 🔐🌍 Привет мир! مرحبا";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithLargePayload_Works()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = new string('x', 100_000);
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_Decrypt_WithJsonPayload_Works()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = "{\"ssn\":\"123-45-6789\",\"credit_card\":\"4111-1111-1111-1111\"}";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
        var decrypted = recipient.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptBytes_DecryptBytes_RoundTrip_Works()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        var plaintext = new byte[] { 0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD };
        var encrypted = EncryptorMlKem.EncryptBytes(plaintext, publicKeyPem);
        var decrypted = recipient.DecryptBytes(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void ExportPrivateKeyPem_ReturnsValidPem()
    {
        using var encryptor = new EncryptorMlKem();

        var pem = encryptor.ExportPrivateKeyPem();

        Assert.Contains("-----BEGIN PRIVATE KEY-----", pem);
        Assert.Contains("-----END PRIVATE KEY-----", pem);
    }

    [Fact]
    public void ExportPublicKeyPem_ReturnsValidPem()
    {
        using var encryptor = new EncryptorMlKem();

        var pem = encryptor.ExportPublicKeyPem();

        Assert.Contains("-----BEGIN PUBLIC KEY-----", pem);
        Assert.Contains("-----END PUBLIC KEY-----", pem);
    }

    [Fact]
    public void Constructor_WithPrivateKeyPem_CanDecrypt()
    {
        using var original = new EncryptorMlKem();
        var privateKeyPem = original.ExportPrivateKeyPem();
        var publicKeyPem = original.ExportPublicKeyPem();

        var plaintext = "Test message";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);

        using var restored = new EncryptorMlKem(privateKeyPem);
        var decrypted = restored.Decrypt(encrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Algorithm_Property_ReturnsCorrectAlgorithm()
    {
        using var encryptor512 = new EncryptorMlKem(MLKemAlgorithm.MLKem512);
        using var encryptor768 = new EncryptorMlKem(MLKemAlgorithm.MLKem768);
        using var encryptor1024 = new EncryptorMlKem(MLKemAlgorithm.MLKem1024);

        Assert.Equal(MLKemAlgorithm.MLKem512, encryptor512.Algorithm);
        Assert.Equal(MLKemAlgorithm.MLKem768, encryptor768.Algorithm);
        Assert.Equal(MLKemAlgorithm.MLKem1024, encryptor1024.Algorithm);
    }

    [Fact]
    public void DefaultConstructor_UsesMLKem768()
    {
        using var encryptor = new EncryptorMlKem();

        Assert.Equal(MLKemAlgorithm.MLKem768, encryptor.Algorithm);
    }

    [Fact]
    public void Encrypt_Decrypt_AcrossAlgorithms_Fails()
    {
        using var sender = new EncryptorMlKem(MLKemAlgorithm.MLKem512);
        using var recipient = new EncryptorMlKem(MLKemAlgorithm.MLKem1024);
        
        var plaintext = "Cross-algorithm test";
        var encrypted = EncryptorMlKem.Encrypt(plaintext, sender.ExportPublicKeyPem());

        // Trying to decrypt with wrong algorithm key should fail
        Assert.ThrowsAny<Exception>(() => recipient.Decrypt(encrypted));
    }

    [Fact]
    public void MultipleEncryptDecrypt_SameInstance_Works()
    {
        using var recipient = new EncryptorMlKem();
        var publicKeyPem = recipient.ExportPublicKeyPem();

        for (int i = 0; i < 10; i++)
        {
            var plaintext = $"Message number {i}";
            var encrypted = EncryptorMlKem.Encrypt(plaintext, publicKeyPem);
            var decrypted = recipient.Decrypt(encrypted);
            Assert.Equal(plaintext, decrypted);
        }
    }
}

#pragma warning restore SYSLIB5006