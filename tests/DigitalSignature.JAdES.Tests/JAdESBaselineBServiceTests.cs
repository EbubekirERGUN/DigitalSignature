using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.JAdES;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DigitalSignature.JAdES.Tests;

public class JAdESBaselineBServiceTests
{
    [Fact]
    public void Canonicalizer_ShouldSortObjectProperties()
    {
        var canonicalizer = new Rfc8785JsonCanonicalizer();
        var canonical = canonicalizer.Canonicalize(Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"));

        Assert.Equal("{\"a\":1,\"b\":2}", canonical);
    }

    [Fact]
    public void CreateDetachedSignature_ShouldProduceCompactJws_AndReadableDescriptor()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Test Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"),
            MimeType: "application/json");
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);

        var envelope = service.CreateDetachedSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-13T12:30:00Z"));
        var descriptor = service.ReadSignature(envelope.CompactSerialization);
        var validation = service.VerifyDetachedSignature(request.Payload, envelope.CompactSerialization, certificate);
        using var protectedHeader = JsonDocument.Parse(DecodeBase64Url(envelope.ProtectedHeader));
        var protectedRoot = protectedHeader.RootElement;

        Assert.Contains('.', envelope.CompactSerialization);
        Assert.Equal("{\"a\":1,\"b\":2}", envelope.CanonicalPayload);
        Assert.Equal(SignatureFormat.JAdES, descriptor.Format);
        Assert.Equal(SignatureLevel.BaselineB, descriptor.Level);
        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
        Assert.Equal("jose", protectedRoot.GetProperty("typ").GetString());
        Assert.Equal("RS256", protectedRoot.GetProperty("alg").GetString());
        Assert.True(protectedRoot.GetProperty("x5c").GetArrayLength() > 0);
        Assert.False(string.IsNullOrWhiteSpace(protectedRoot.GetProperty("x5t#S256").GetString()));
        Assert.Equal("sigT", protectedRoot.GetProperty("crit")[0].GetString());
    }

    [Fact]
    public void CreateDetachedJsonSignature_ShouldProduceGeneralJsonSerialization()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Test Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"),
            MimeType: "application/json");
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);

        var envelope = service.CreateDetachedJsonSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-13T12:30:00Z"));
        using var document = JsonDocument.Parse(envelope.JsonDocument);
        using var protectedHeader = JsonDocument.Parse(envelope.ProtectedHeaderJson);
        var root = document.RootElement;
        var protectedRoot = protectedHeader.RootElement;

        var signatures = root.GetProperty("signatures");
        var signatureEntry = signatures[0];
        var kid = protectedRoot.GetProperty("kid").GetString();

        Assert.Equal(JsonValueKind.String, root.GetProperty("payload").ValueKind);
        Assert.Equal(JsonValueKind.Array, signatures.ValueKind);
        Assert.Equal(1, signatures.GetArrayLength());
        Assert.Equal(JsonValueKind.String, signatureEntry.GetProperty("protected").ValueKind);
        Assert.Equal(JsonValueKind.String, signatureEntry.GetProperty("signature").ValueKind);
        Assert.False(root.TryGetProperty("protected", out _));
        Assert.False(root.TryGetProperty("signature", out _));
        Assert.Equal("jose+json", protectedRoot.GetProperty("typ").GetString());
        Assert.True(protectedRoot.GetProperty("x5c").GetArrayLength() > 0);
        Assert.False(string.IsNullOrWhiteSpace(protectedRoot.GetProperty("x5t#S256").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(kid));
        AssertIssuerSerial(DecodeBase64(kid!));
    }

    [Fact]
    public void CreateSignatureTimestampRequest_ShouldHashBase64UrlEncodedSignatureValue()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Test Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"),
            MimeType: "application/json");
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);

        var envelope = service.CreateDetachedJsonSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-13T12:30:00Z"));
        var timestampRequest = service.CreateSignatureTimestampRequest(envelope, HashAlgorithmIdentifier.Sha256, nonceHex: "AA");
        var expectedDigest = SHA256.HashData(Encoding.ASCII.GetBytes(envelope.Signature));

        Assert.Equal(expectedDigest, timestampRequest.HashedMessage.ToArray());
        Assert.Equal("SHA-256", timestampRequest.HashAlgorithm);
        Assert.Equal("AA", timestampRequest.Nonce);
    }

    [Fact]
    public async Task AttachSignatureTimestamp_ShouldProduceBaselineTJsonSignature()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=JAdES Test TSA");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate);
        var request = new SignatureRequest(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"),
            MimeType: "application/json");
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);

        var baselineBEnvelope = service.CreateDetachedJsonSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-13T12:30:00Z"));
        var timestamp = await CreateSignatureTimestampAsync(service, baselineBEnvelope, timestampProvider, suite.HashAlgorithm);
        var baselineTEnvelope = service.AttachSignatureTimestamp(baselineBEnvelope, timestamp);
        var descriptor = service.ReadJsonSignature(baselineTEnvelope.JsonDocument);
        var validation = service.VerifyDetachedJsonSignature(request.Payload, baselineTEnvelope.JsonDocument, certificate);
        var etsiUComponentNames = ReadEtsiUComponentNames(baselineTEnvelope.HeaderJson!);

        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
        Assert.Equal(SignatureLevel.BaselineT, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.Timestamps);
        Assert.Equal(new[] { "sigTst" }, etsiUComponentNames);
    }

    [Fact]
    public async Task AttachValidationMaterial_ShouldProduceBaselineLTJsonSignature()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Test Signer");
        using var tsaKey = RSA.Create(2048);
        using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=JAdES Test TSA");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate);
        var request = new SignatureRequest(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"),
            MimeType: "application/json");
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);

        var baselineBEnvelope = service.CreateDetachedJsonSignature(request, certificate, rsa, suite, DateTimeOffset.Parse("2026-04-13T12:30:00Z"));
        var timestamp = await CreateSignatureTimestampAsync(service, baselineBEnvelope, timestampProvider, suite.HashAlgorithm);
        var baselineTEnvelope = service.AttachSignatureTimestamp(baselineBEnvelope, timestamp);
        var baselineLTEnvelope = service.AttachValidationMaterial(
            baselineTEnvelope,
            [certificate, tsaCertificate],
            [
                CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-14T08:02:00Z")),
                CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.Parse("2026-04-14T08:03:00Z"))
            ]);

        var descriptor = service.ReadJsonSignature(baselineLTEnvelope.JsonDocument);
        var validation = service.VerifyDetachedJsonSignature(request.Payload, baselineLTEnvelope.JsonDocument, certificate);
        var etsiUComponentNames = ReadEtsiUComponentNames(baselineLTEnvelope.HeaderJson!);

        Assert.Equal(ValidationConclusion.Valid, validation.Conclusion);
        Assert.Equal(SignatureLevel.BaselineLT, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.Timestamps);
        Assert.NotEmpty(descriptor.ValidationMaterial.CertificateValues);
        Assert.NotEmpty(descriptor.ValidationMaterial.RevocationValues);
        Assert.NotEmpty(descriptor.ValidationMaterial.RevocationInfo);
        Assert.Equal(new[] { "sigTst", "xVals", "rVals" }, etsiUComponentNames);
    }

    [Fact]
    public void VerifyDetachedSignature_ShouldFail_WhenPayloadCanonicalizationDiffers()
    {
        using var rsa = RSA.Create(2048);
        using var certificate = CreateSelfSignedCertificate(rsa, "CN=JAdES Test Signer");

        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            Encoding.UTF8.GetBytes("{\"b\":2,\"a\":1}"));
        var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048);
        var envelope = service.CreateDetachedSignature(request, certificate, rsa, suite);

        var validation = service.VerifyDetachedSignature(Encoding.UTF8.GetBytes("{\"a\":9,\"b\":2}"), envelope.CompactSerialization, certificate);

        Assert.Equal(ValidationConclusion.Invalid, validation.Conclusion);
        Assert.Contains(validation.Failures, failure => failure.Code == ValidationErrorCodes.HashMismatch);
    }

    private static async Task<TimestampMaterial> CreateSignatureTimestampAsync(
        JAdESBaselineBService service,
        JAdESJsonSignatureEnvelope envelope,
        ITimestampProvider timestampProvider,
        HashAlgorithmIdentifier hashAlgorithm)
    {
        var response = await timestampProvider.GetTimestampAsync(service.CreateSignatureTimestampRequest(envelope, hashAlgorithm));

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.Timestamp);
        return response.Timestamp!;
    }

    private static IReadOnlyList<string> ReadEtsiUComponentNames(string headerJson)
    {
        using var document = JsonDocument.Parse(headerJson);
        return document.RootElement
            .GetProperty("etsiU")
            .EnumerateArray()
            .Select(item => item.ValueKind == JsonValueKind.String ? DecodeBase64Url(item.GetString()!) : item.GetRawText())
            .Select(componentJson =>
            {
                using var componentDocument = JsonDocument.Parse(componentJson);
                return componentDocument.RootElement.EnumerateObject().Single().Name;
            })
            .ToArray();
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

    private static string DecodeBase64Url(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
    }

    private static byte[] DecodeBase64(string value) => Convert.FromBase64String(value);

    private static void AssertIssuerSerial(byte[] encodedIssuerSerial)
    {
        var reader = new AsnReader(encodedIssuerSerial, AsnEncodingRules.DER);
        var issuerSerial = reader.ReadSequence();
        var generalNames = issuerSerial.ReadSequence();
        var directoryNameTag = new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true);
        var directoryName = generalNames.ReadSequence(directoryNameTag);

        Assert.NotEmpty(directoryName.ReadEncodedValue().Span.ToArray());
        Assert.True(generalNames.HasData is false);
        Assert.True(issuerSerial.ReadInteger() > 0);
        Assert.False(issuerSerial.HasData);
        Assert.False(reader.HasData);
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
