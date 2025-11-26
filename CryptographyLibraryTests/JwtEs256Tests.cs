using System.Text.Json;
using CryptographyLibrary;

namespace CryptographyLibraryTests;

public class JwtEs256Tests
{
    [Fact]
    public void Create_ReturnsValidJwtFormat()
    {
        var jwt = new JwtEs256();
        var payload = "{\"sub\":\"123\"}";

        var token = jwt.Create(payload);

        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.All(parts, part => Assert.False(string.IsNullOrEmpty(part)));
    }

    [Fact]
    public void Create_HeaderContainsCorrectAlgorithm()
    {
        var jwt = new JwtEs256();
        var payload = "{\"test\":\"data\"}";

        var token = jwt.Create(payload);

        var headerBase64 = token.Split('.')[0];
        var headerJson = Base64UrlDecode(headerBase64);
        var header = JsonDocument.Parse(headerJson);
        
        Assert.Equal("ES256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
    }

    [Fact]
    public void Verify_ValidToken_ReturnsTrue()
    {
        var jwt = new JwtEs256();
        var payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}";

        var token = jwt.Create(payload);
        var result = jwt.Verify(token, out var extractedPayload);

        Assert.True(result);
        Assert.Equal(payload, extractedPayload);
    }

    [Fact]
    public void Verify_TamperedPayload_ReturnsFalse()
    {
        var jwt = new JwtEs256();
        var payload = "{\"sub\":\"123\"}";

        var token = jwt.Create(payload);
        var parts = token.Split('.');
        var tamperedPayload = Base64UrlEncode("{\"sub\":\"456\"}");
        var tamperedToken = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        var result = jwt.Verify(tamperedToken, out var extractedPayload);

        Assert.False(result);
        Assert.Null(extractedPayload);
    }

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalse()
    {
        var jwt = new JwtEs256();
        var payload = "{\"sub\":\"123\"}";

        var token = jwt.Create(payload);
        var parts = token.Split('.');
        var tamperedToken = $"{parts[0]}.{parts[1]}.invalidsignature";

        var result = jwt.Verify(tamperedToken, out var extractedPayload);

        Assert.False(result);
        Assert.Null(extractedPayload);
    }

    [Fact]
    public void Verify_InvalidFormat_ReturnsFalse()
    {
        var jwt = new JwtEs256();

        var result = jwt.Verify("not.a.valid.token.format", out var payload);

        Assert.False(result);
        Assert.Null(payload);
    }

    [Fact]
    public void Verify_EmptyString_ReturnsFalse()
    {
        var jwt = new JwtEs256();

        var result = jwt.Verify("", out var payload);

        Assert.False(result);
        Assert.Null(payload);
    }

    [Fact]
    public void Verify_DifferentKeyPair_ReturnsFalse()
    {
        var jwt1 = new JwtEs256();
        var jwt2 = new JwtEs256();
        var payload = "{\"sub\":\"123\"}";

        var token = jwt1.Create(payload);
        var result = jwt2.Verify(token, out var extractedPayload);

        Assert.False(result);
        Assert.Null(extractedPayload);
    }

    [Fact]
    public void Constructor_WithPemKeys_CanVerifyTokens()
    {
        var jwt1 = new JwtEs256();
        var privateKeyPem = jwt1.ExportPrivateKeyPem();
        var publicKeyPem = jwt1.ExportPublicKeyPem();
        var payload = "{\"sub\":\"123\"}";

        var token = jwt1.Create(payload);
        var jwt2 = new JwtEs256(privateKeyPem, publicKeyPem);
        var result = jwt2.Verify(token, out var extractedPayload);

        Assert.True(result);
        Assert.Equal(payload, extractedPayload);
    }

    [Fact]
    public void Create_WithSpecialCharacters_RoundTripsCorrectly()
    {
        var jwt = new JwtEs256();
        var payload = "{\"message\":\"Hello, 世界! 🌍\",\"special\":\"<>&\\\"\"}";

        var token = jwt.Create(payload);
        var result = jwt.Verify(token, out var extractedPayload);

        Assert.True(result);
        Assert.Equal(payload, extractedPayload);
    }

    [Fact]
    public void Create_WithLargePayload_Works()
    {
        var jwt = new JwtEs256();
        var largeData = new string('x', 10000);
        var payload = $"{{\"data\":\"{largeData}\"}}";

        var token = jwt.Create(payload);
        var result = jwt.Verify(token, out var extractedPayload);

        Assert.True(result);
        Assert.Equal(payload, extractedPayload);
    }

    [Fact]
    public void ExportPrivateKeyPem_ReturnsValidPem()
    {
        var jwt = new JwtEs256();

        var pem = jwt.ExportPrivateKeyPem();

        Assert.Contains("-----BEGIN EC PRIVATE KEY-----", pem);
        Assert.Contains("-----END EC PRIVATE KEY-----", pem);
    }

    [Fact]
    public void ExportPublicKeyPem_ReturnsValidPem()
    {
        var jwt = new JwtEs256();

        var pem = jwt.ExportPublicKeyPem();

        Assert.Contains("-----BEGIN PUBLIC KEY-----", pem);
        Assert.Contains("-----END PUBLIC KEY-----", pem);
    }

    [Fact]
    public void Verify_WrongAlgorithmInHeader_ReturnsFalse()
    {
        var jwt = new JwtEs256();
        var payload = "{\"sub\":\"123\"}";

        var token = jwt.Create(payload);
        var parts = token.Split('.');
        var wrongHeader = Base64UrlEncode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        var tamperedToken = $"{wrongHeader}.{parts[1]}.{parts[2]}";

        var result = jwt.Verify(tamperedToken, out var extractedPayload);

        Assert.False(result);
        Assert.Null(extractedPayload);
    }

    private static string Base64UrlEncode(string data)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(data);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string Base64UrlDecode(string base64Url)
    {
        var base64 = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64));
    }
    
    [Fact]
    public void VerifyOnlyInstance_CannotCreateTokens()
    {
        var issuer = new JwtEs256();
        var verifier = JwtEs256.CreateVerifier(issuer.ExportPublicKeyPem());

        Assert.Throws<InvalidOperationException>(() =>
            verifier.Create("{\"test\":\"payload\"}")
        );
    }

    [Fact]
    public void VerifyOnlyInstance_CannotExportPrivateKey()
    {
        var issuer = new JwtEs256();
        var verifier = JwtEs256.CreateVerifier(issuer.ExportPublicKeyPem());

        Assert.Throws<InvalidOperationException>(() =>
            verifier.ExportPrivateKeyPem()
        );
    }

    [Fact]
    public void VerifyOnlyInstance_CanVerifyValidToken()
    {
        var issuer = new JwtEs256();
        var verifier = JwtEs256.CreateVerifier(issuer.ExportPublicKeyPem());

        var token = issuer.Create("{\"sub\":\"123\"}");

        Assert.True(verifier.Verify(token, out var payload));
        Assert.Contains("123", payload);
    }

    [Fact]
    public void VerifyOnlyInstance_RejectsInvalidToken()
    {
        var issuer = new JwtEs256();
        var fakeIssuer = new JwtEs256();
        var verifier = JwtEs256.CreateVerifier(issuer.ExportPublicKeyPem());

        var fakeToken = fakeIssuer.Create("{\"sub\":\"123\"}");

        Assert.False(verifier.Verify(fakeToken, out _));
    }
}