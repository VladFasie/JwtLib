using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JwtLib;

public class JwtEs256
{
    private readonly ECDsa _privateKey;
    private readonly ECDsa _publicKey;

    public JwtEs256()
    {
        _privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _publicKey = ECDsa.Create();
        _publicKey.ImportParameters(_privateKey.ExportParameters(false));
    }

    public JwtEs256(string privateKeyPem, string publicKeyPem)
    {
        _privateKey = ECDsa.Create();
        _privateKey.ImportFromPem(privateKeyPem);
        
        _publicKey = ECDsa.Create();
        _publicKey.ImportFromPem(publicKeyPem);
    }

    public JwtEs256(ECDsa privateKey, ECDsa publicKey)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    public string Create(string payload)
    {
        var header = new { alg = "ES256", typ = "JWT" };
        var headerJson = JsonSerializer.Serialize(header);
        var headerBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payload));

        var dataToSign = $"{headerBase64}.{payloadBase64}";
        var dataBytes = Encoding.UTF8.GetBytes(dataToSign);
        
        var signature = _privateKey.SignData(dataBytes, HashAlgorithmName.SHA256);
        var signatureBase64 = Base64UrlEncode(signature);

        return $"{headerBase64}.{payloadBase64}.{signatureBase64}";
    }

    public bool Verify(string token, out string payload)
    {
        payload = null;
        
        var parts = token.Split('.');
        if (parts.Length != 3)
            return false;

        var headerBase64 = parts[0];
        var payloadBase64 = parts[1];
        var signatureBase64 = parts[2];

        try
        {
            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(headerBase64));
            var headerDoc = JsonDocument.Parse(headerJson);
            
            if (!headerDoc.RootElement.TryGetProperty("alg", out var algElement) || 
                algElement.GetString() != "ES256")
                return false;

            var dataToVerify = $"{headerBase64}.{payloadBase64}";
            var dataBytes = Encoding.UTF8.GetBytes(dataToVerify);
            var signature = Base64UrlDecode(signatureBase64);

            if (!_publicKey.VerifyData(dataBytes, signature, HashAlgorithmName.SHA256))
                return false;

            payload = Encoding.UTF8.GetString(Base64UrlDecode(payloadBase64));
            return true;
        }
        catch
        {
            return false;
        }
    }

    public string ExportPrivateKeyPem()
    {
        return _privateKey.ExportECPrivateKeyPem();
    }

    public string ExportPublicKeyPem()
    {
        return _publicKey.ExportSubjectPublicKeyInfoPem();
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        var base64 = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        return Convert.FromBase64String(base64);
    }
}