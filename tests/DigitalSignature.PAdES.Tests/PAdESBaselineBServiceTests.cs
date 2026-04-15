using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using DigitalSignature.PAdES;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DigitalSignature.PAdES.Tests;

public class PAdESBaselineBServiceTests
{
    [Fact]
    public void PrepareDetachedSignaturePlaceholder_ShouldAppendPdfSignatureDictionary()
    {
        var service = new PAdESBaselineBService();
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");

        var result = service.PrepareDetachedSignaturePlaceholder(pdf, 200);
        var rendered = Encoding.ASCII.GetString(result.Document.Span);

        Assert.Contains("/Type /Sig", rendered);
        Assert.Contains("/SubFilter /ETSI.CAdES.detached", rendered);
        Assert.Equal(200, result.Placeholder.ContentsLength);
        Assert.Equal(0, result.Placeholder.ByteRange.StartOffset);
        Assert.True(result.Placeholder.ByteRange.FirstLength > 0);
        Assert.True(result.Placeholder.ByteRange.SecondLength >= 0);
    }

    [Fact]
    public void ApplyDetachedSignature_ShouldEmbedHexSignature_AndReplaceByteRangeToken()
    {
        var service = new PAdESBaselineBService();
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
        var binding = service.PrepareDetachedSignaturePlaceholder(pdf, 20);

        var signed = service.ApplyDetachedSignature(binding, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        var rendered = Encoding.ASCII.GetString(signed.Span);

        Assert.Contains("DEADBEEF", rendered);
        Assert.DoesNotContain("**********", rendered);
    }

    [Fact]
    public void CreateSignatureDescriptor_ShouldDescribePAdESBaselineB()
    {
        var service = new PAdESBaselineBService();

        var descriptor = service.CreateSignatureDescriptor();

        Assert.Equal(SignatureFormat.PAdES, descriptor.Format);
        Assert.Equal(SignatureLevel.BaselineB, descriptor.Level);
    }

    [Fact]
    public async Task AugmentToBaselineLT_ShouldAppendDssAndVri_WhenValidationMaterialIsProvided()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=PAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=PAdES Test TSA");

        var service = new PAdESBaselineBService();
        var cadesService = new CAdESBaselineBService();
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate, fixedTimestamp: DateTimeOffset.UtcNow.AddMinutes(-5));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
        var binding = service.PrepareDetachedSignaturePlaceholder(pdf, 8192);
        var prepared = service.PrepareDetachedSignatureInput(binding);
        var signingTime = DateTimeOffset.UtcNow.AddMinutes(-10);

        var baselineBSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, prepared.SignedBytes),
            certificate,
            rsa,
            suite,
            signingTime,
            includeSigningTime: false);
        var timestamp = await CreateTimestampForSignerInfoAsync(prepared.SignedBytes, baselineBSignature.Data, timestampProvider);
        var baselineTSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineT, prepared.SignedBytes),
            certificate,
            rsa,
            suite,
            signingTime,
            signatureTimestamp: timestamp,
            includeSigningTime: false);
        var signedPdf = service.ApplyDetachedSignature(prepared, baselineTSignature.Data);

        var baselineLtPdf = service.AugmentToBaselineLT(
            signedPdf,
            [
                CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.UtcNow.AddMinutes(-8)),
                CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.UtcNow.AddMinutes(-7))
            ],
            [certificate, tsaCertificate]);

        var rendered = Encoding.Latin1.GetString(baselineLtPdf.Span);
        var contentsStart = rendered.IndexOf("/Contents <", StringComparison.Ordinal);
        Assert.True(contentsStart >= 0);
        var hexStart = contentsStart + "/Contents <".Length;
        var hexEnd = rendered.IndexOf('>', hexStart);
        Assert.True(hexEnd > hexStart);
        var rawContentsBytes = Convert.FromHexString(rendered.Substring(hexStart, hexEnd - hexStart));
        var expectedVriKey = Convert.ToHexString(SHA1.HashData(rawContentsBytes));

        Assert.Contains("/DSS", rendered);
        Assert.Contains("/VRI", rendered);
        Assert.Contains("/Certs", rendered);
        Assert.Contains("/CRLs", rendered);
        Assert.Contains($"/{expectedVriKey}", rendered);
    }

    private static async Task<TimestampMaterial> CreateTimestampForSignerInfoAsync(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature,
        ITimestampProvider timestampProvider)
    {
        var signedCms = new SignedCms(new ContentInfo(payload.ToArray()), detached: true);
        signedCms.Decode(signature.ToArray());
        var timestampRequest = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signedCms.SignerInfos[0],
            HashAlgorithmName.SHA256,
            null,
            null,
            true,
            null);

        var response = await timestampProvider.GetTimestampAsync(
            new TimestampRequest(
                timestampRequest.GetMessageHash(),
                timestampRequest.HashAlgorithmId.Value!,
                timestampRequest.RequestedPolicyId?.Value,
                timestampRequest.GetNonce() is { } nonce ? Convert.ToHexString(nonce.Span) : null,
                timestampRequest.RequestSignerCertificate));

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.Timestamp);
        return response.Timestamp!;
    }

    private static RevocationInfo CreateCrlRevocationInfo(
        X509Certificate2 certificate,
        RSA issuerKey,
        DateTimeOffset thisUpdate)
    {
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(DotNetUtilities.FromX509Certificate(certificate).SubjectDN);
        generator.SetThisUpdate(thisUpdate.UtcDateTime);
        generator.SetNextUpdate(thisUpdate.AddDays(7).UtcDateTime);

        var crl = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", DotNetUtilities.GetRsaKeyPair(issuerKey).Private));
        return new RevocationInfo(
            "CRL",
            thisUpdate,
            thisUpdate.AddDays(7),
            false,
            null)
        {
            EncodedValue = crl.GetEncoded()
        };
    }

    private static X509Certificate2 CreateSelfSignedCertificate(RSA rsa, string subjectName)
    {
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
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
