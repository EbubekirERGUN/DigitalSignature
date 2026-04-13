using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.Core.Tests;

public class LocalRfc3161TimestampProviderTests
{
    [Fact]
    public async Task GetTimestampAsync_ShouldProduceDecodableTimestampToken()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateTsaCertificate(rsa, "CN=Local TSA");

        var provider = new LocalRfc3161TimestampProvider(certificate, fixedTimestamp: DateTimeOffset.Parse("2026-04-13T18:00:00Z"));
        var payload = "timestamped payload"u8.ToArray();
        var request = new TimestampRequest(SHA256.HashData(payload), "SHA-256", "1.2.3.4.5");

        var response = await provider.GetTimestampAsync(request);

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.Timestamp);
        Assert.True(Rfc3161TimestampToken.TryDecode(response.Timestamp!.Token, out var token, out _));
        Assert.NotNull(token);
        Assert.True(token!.VerifySignatureForData(payload, out var signerCertificate, null));
        Assert.Equal(certificate.Subject, signerCertificate!.Subject);
        Assert.Equal("1.2.3.4.5", token.TokenInfo.PolicyId.Value);
    }

    private static X509Certificate2 CreateTsaCertificate(RSA rsa, string subjectName)
    {
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));

        var enhancedKeyUsages = new OidCollection { new("1.3.6.1.5.5.7.3.8") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, true));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
