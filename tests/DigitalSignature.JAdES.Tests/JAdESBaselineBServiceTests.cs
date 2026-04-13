using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.JAdES;

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
}
