using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;

namespace DigitalSignature.Core.Tests;

public class LocalRfc3161TimestampProviderTests
{
    [Fact]
    public async Task GetTimestampAsync_ShouldProduceDecodableTimestampToken()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateTsaCertificate(rsa, "CN=Local TSA");

        var provider = new LocalRfc3161TimestampProvider(certificate, fixedTimestamp: DateTimeOffset.UtcNow);
        var payload = "timestamped payload"u8.ToArray();
        var request = new TimestampRequest(SHA256.HashData(payload), "SHA-256", "1.2.3.4.5");

        var response = await provider.GetTimestampAsync(request);

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.Timestamp);

        var token = new TimeStampToken(new CmsSignedData(response.Timestamp!.Token.ToArray()));
        var signerCertificate = token.GetCertificates().EnumerateMatches(token.SignerID).Single();
        var signer = token.ToCmsSignedData().GetSignerInfos().GetSigners().Cast<SignerInformation>().Single();

        Assert.True(signer.Verify(signerCertificate));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(payload)), Convert.ToHexString(token.TimeStampInfo.GetMessageImprintDigest()));
        Assert.Equal(certificate.Subject, DotNetUtilities.ToX509Certificate(signerCertificate).Subject);
        Assert.Equal("1.2.3.4.5", token.TimeStampInfo.Policy);
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
