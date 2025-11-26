using System.Security.Cryptography;
using System.Text;

namespace CryptographyLibrary;

/// <summary>
/// Encryption using ECDH (Elliptic Curve Diffie-Hellman) + AES-CBC.
/// Uses the ECIES pattern for public-key encryption.
/// Intended for use within authenticated contexts (e.g., JWT signatures).
/// </summary>
public class EncryptorEcdh : IDisposable
{
    private readonly ECDiffieHellman _privateKey;
    private bool _disposed;

    /// <summary>
    /// Creates a new instance with auto-generated keys using P-256 curve.
    /// </summary>
    public EncryptorEcdh()
    {
        _privateKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    }

    /// <summary>
    /// Creates an instance from a PEM-encoded private key (for decryption).
    /// </summary>
    public EncryptorEcdh(string privateKeyPem)
    {
        _privateKey = ECDiffieHellman.Create();
        _privateKey.ImportFromPem(privateKeyPem);
    }

    /// <summary>
    /// Encrypts a string for a recipient using their public key.
    /// </summary>
    /// <param name="plaintext">The string to encrypt.</param>
    /// <param name="recipientPublicKeyPem">Recipient's ECDH public key in PEM format.</param>
    /// <returns>Base64-encoded ciphertext (ephemeral public key + IV + encrypted data).</returns>
    public static string Encrypt(string plaintext, string recipientPublicKeyPem)
    {
        var data = Encoding.UTF8.GetBytes(plaintext);
        var encryptedBytes = EncryptBytes(data, recipientPublicKeyPem);
        return Convert.ToBase64String(encryptedBytes);
    }

    /// <summary>
    /// Encrypts bytes for a recipient using their public key.
    /// </summary>
    public static byte[] EncryptBytes(byte[] plaintext, string recipientPublicKeyPem)
    {
        // Import recipient's public key
        using var recipientKey = ECDiffieHellman.Create();
        recipientKey.ImportFromPem(recipientPublicKeyPem);

        // Generate ephemeral key pair for this encryption
        using var ephemeralKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        // Derive shared secret using ECDH
        var sharedSecret = ephemeralKey.DeriveKeyMaterial(recipientKey.PublicKey);

        // Derive AES key from shared secret
        var aesKey = DeriveAesKey(sharedSecret);

        // Generate random IV
        var iv = new byte[16];
        RandomNumberGenerator.Fill(iv);

        // Encrypt with AES-CBC
        byte[] encrypted;
        using (var aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            encrypted = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        // Export ephemeral public key (uncompressed point format)
        var ephemeralPublicKey = ephemeralKey.ExportSubjectPublicKeyInfo();

        // Clear sensitive data
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(aesKey);

        // Output: ephemeral public key length (4 bytes) || ephemeral public key || IV || encrypted data
        var result = new byte[4 + ephemeralPublicKey.Length + iv.Length + encrypted.Length];
        BitConverter.TryWriteBytes(result.AsSpan(0, 4), ephemeralPublicKey.Length);
        Buffer.BlockCopy(ephemeralPublicKey, 0, result, 4, ephemeralPublicKey.Length);
        Buffer.BlockCopy(iv, 0, result, 4 + ephemeralPublicKey.Length, iv.Length);
        Buffer.BlockCopy(encrypted, 0, result, 4 + ephemeralPublicKey.Length + iv.Length, encrypted.Length);

        return result;
    }

    /// <summary>
    /// Decrypts a Base64-encoded ciphertext using this instance's private key.
    /// </summary>
    /// <param name="encryptedBase64">Base64-encoded ciphertext from Encrypt().</param>
    /// <returns>The decrypted string.</returns>
    public string Decrypt(string encryptedBase64)
    {
        var encryptedBytes = Convert.FromBase64String(encryptedBase64);
        var decryptedBytes = DecryptBytes(encryptedBytes);
        return Encoding.UTF8.GetString(decryptedBytes);
    }

    /// <summary>
    /// Decrypts bytes using this instance's private key.
    /// </summary>
    public byte[] DecryptBytes(byte[] encrypted)
    {
        const int ivLength = 16;

        if (encrypted.Length < 4)
            throw new CryptographicException("Invalid encrypted data length.");

        // Extract ephemeral public key length
        var ephemeralKeyLength = BitConverter.ToInt32(encrypted.AsSpan(0, 4));

        if (encrypted.Length < 4 + ephemeralKeyLength + ivLength + 1)
            throw new CryptographicException("Invalid encrypted data length.");

        // Extract components
        var ephemeralPublicKeyBytes = new byte[ephemeralKeyLength];
        var iv = new byte[ivLength];
        var encryptedData = new byte[encrypted.Length - 4 - ephemeralKeyLength - ivLength];

        Buffer.BlockCopy(encrypted, 4, ephemeralPublicKeyBytes, 0, ephemeralKeyLength);
        Buffer.BlockCopy(encrypted, 4 + ephemeralKeyLength, iv, 0, ivLength);
        Buffer.BlockCopy(encrypted, 4 + ephemeralKeyLength + ivLength, encryptedData, 0, encryptedData.Length);

        // Import ephemeral public key
        using var ephemeralKey = ECDiffieHellman.Create();
        ephemeralKey.ImportSubjectPublicKeyInfo(ephemeralPublicKeyBytes, out _);

        // Derive shared secret using ECDH
        var sharedSecret = _privateKey.DeriveKeyMaterial(ephemeralKey.PublicKey);

        // Derive AES key
        var aesKey = DeriveAesKey(sharedSecret);

        // Decrypt with AES-CBC
        byte[] decrypted;
        using (var aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            decrypted = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }

        // Clear sensitive data
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(aesKey);

        return decrypted;
    }

    /// <summary>
    /// Exports the private key in PEM format.
    /// </summary>
    public string ExportPrivateKeyPem()
    {
        return _privateKey.ExportECPrivateKeyPem();
    }

    /// <summary>
    /// Exports the public key in PEM format.
    /// </summary>
    public string ExportPublicKeyPem()
    {
        return _privateKey.ExportSubjectPublicKeyInfoPem();
    }

    private static byte[] DeriveAesKey(byte[] sharedSecret)
    {
        return SHA256.HashData(sharedSecret);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _privateKey.Dispose();
            _disposed = true;
        }
    }
}