using System.Security.Cryptography;
using System.Text;

namespace CryptographyLibrary.PostQuantumCryptography;

#pragma warning disable SYSLIB5006 // ML-KEM is experimental in .NET 10

/// <summary>
/// Post-quantum encryption using ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) (FIPS 203) + AES-CBC (Cipher Block Chaining).
/// Intended for use within authenticated contexts (e.g., JWT signatures).
/// </summary>
public class EncryptorMlKem : IDisposable
{
    private readonly MLKem _privateKey;
    private bool _disposed;

    private const int SharedSecretSize = 32; // Always 32 bytes per FIPS 203

    /// <summary>
    /// Creates a new instance with auto-generated keys using ML-KEM-768 (192-bit security).
    /// </summary>
    public EncryptorMlKem() : this(MLKemAlgorithm.MLKem768)
    {
    }

    /// <summary>
    /// Creates a new instance with the specified algorithm.
    /// </summary>
    public EncryptorMlKem(MLKemAlgorithm algorithm)
    {
        Algorithm = algorithm;
        _privateKey = MLKem.GenerateKey(algorithm);
    }

    /// <summary>
    /// Creates an instance from a PEM-encoded private key (for decryption).
    /// </summary>
    public EncryptorMlKem(string privateKeyPem)
    {
        _privateKey = MLKem.ImportFromPem(privateKeyPem);
        Algorithm = _privateKey.Algorithm;
    }

    /// <summary>
    /// Gets the algorithm used by this instance.
    /// </summary>
    public MLKemAlgorithm Algorithm { get; }

    /// <summary>
    /// Encrypts a string for a recipient using their public key.
    /// </summary>
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
        using var recipientKey = MLKem.ImportFromPem(recipientPublicKeyPem);
        
        int ciphertextSize = GetCiphertextSize(recipientKey.Algorithm);
        var ciphertext = new byte[ciphertextSize];
        var sharedSecret = new byte[SharedSecretSize];

        // Encapsulate: fills both buffers
        recipientKey.Encapsulate(ciphertext, sharedSecret);

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

        // Clear sensitive data
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(aesKey);

        // Output: ciphertext || IV || encrypted data
        var result = new byte[ciphertext.Length + iv.Length + encrypted.Length];
        Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
        Buffer.BlockCopy(iv, 0, result, ciphertext.Length, iv.Length);
        Buffer.BlockCopy(encrypted, 0, result, ciphertext.Length + iv.Length, encrypted.Length);

        return result;
    }

    /// <summary>
    /// Decrypts a Base64-encoded ciphertext using this instance's private key.
    /// </summary>
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
        var ciphertextLength = GetCiphertextSize(Algorithm);
        const int ivLength = 16;

        if (encrypted.Length < ciphertextLength + ivLength + 1)
            throw new CryptographicException("Invalid encrypted data length.");

        // Extract components
        var ciphertext = new byte[ciphertextLength];
        var iv = new byte[ivLength];
        var encryptedData = new byte[encrypted.Length - ciphertextLength - ivLength];

        Buffer.BlockCopy(encrypted, 0, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(encrypted, ciphertextLength, iv, 0, ivLength);
        Buffer.BlockCopy(encrypted, ciphertextLength + ivLength, encryptedData, 0, encryptedData.Length);

        // Decapsulate to get shared secret
        var sharedSecret = new byte[SharedSecretSize];
        _privateKey.Decapsulate(ciphertext, sharedSecret);

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
        return _privateKey.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>
    /// Exports the public key in PEM format.
    /// </summary>
    public string ExportPublicKeyPem()
    {
        return _privateKey.ExportSubjectPublicKeyInfoPem();
    }

    private static int GetCiphertextSize(MLKemAlgorithm algorithm)
    {
        // FIPS 203 fixed ciphertext sizes
        if (algorithm == MLKemAlgorithm.MLKem512) return 768;
        if (algorithm == MLKemAlgorithm.MLKem768) return 1088;
        if (algorithm == MLKemAlgorithm.MLKem1024) return 1568;
        throw new NotSupportedException("Unknown ML-KEM algorithm");
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

#pragma warning restore SYSLIB5006