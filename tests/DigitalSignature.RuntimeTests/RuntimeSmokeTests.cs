using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DigitalSignature.Abstractions;
using DigitalSignature.ASiC;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using DigitalSignature.JAdES;
using DigitalSignature.PAdES;
using DigitalSignature.XAdES;

namespace DigitalSignature.RuntimeTests;

public class RuntimeSmokeTests
{
    [Fact]
    public void ASiC_RuntimeSmoke_ShouldCreateAndVerifyContainer()
    {
        using var material = new RuntimeMaterial();
        var service = new ASiCSBaselineBService();
        var request = new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, RuntimeSmokeFixtures.AsicPayload);

        var artifact = service.CreateContainer(request, "runtime.txt", material.Certificate, material.Key, material.Suite);
        var verification = service.VerifyContainer(artifact.Container.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.True(verification.IsMimeTypeFileFirst);
        Assert.True(verification.IsMimeTypeFileStored);
        Assert.Equal("runtime.txt", verification.PayloadEntryName);
    }

    [Fact]
    public async Task ASiC_RuntimeSmoke_ShouldCreateAndVerifyBaselineTContainer()
    {
        using var material = new RuntimeMaterial();
        var service = new ASiCSBaselineBService();
        var baselineBRequest = new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, RuntimeSmokeFixtures.AsicPayload);

        var baselineBArtifact = service.CreateContainer(baselineBRequest, "runtime.txt", material.Certificate, material.Key, material.Suite);
        var timestampMaterial = await CreateTimestampForDetachedSignatureInsideContainerAsync(
            baselineBArtifact.Container.Data,
            baselineBRequest.Payload,
            material.TimestampProvider);

        var baselineTArtifact = service.CreateContainer(
            baselineBRequest with { Level = SignatureLevel.BaselineT },
            "runtime.txt",
            material.Certificate,
            material.Key,
            material.Suite,
            signatureTimestamp: timestampMaterial);
        var verification = service.VerifyContainer(baselineTArtifact.Container.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.NotNull(verification.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineT, verification.Validation.Signature!.Level);
        Assert.Single(verification.Validation.Signature.ValidationMaterial.Timestamps);
    }

    [Fact]
    public void CAdES_RuntimeSmoke_ShouldCreateAndVerifyDetachedSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new CAdESBaselineBService();
        var request = new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.CadesPayload);

        var artifact = service.CreateDetachedSignature(request, material.Certificate, material.Key, material.Suite);
        var verification = service.VerifyDetachedSignature(request.Payload, artifact.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.NotEmpty(artifact.Data.ToArray());
    }

    [Fact]
    public async Task CAdES_RuntimeSmoke_ShouldCreateAndVerifyAttachedBaselineTSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new CAdESBaselineBService();
        var baselineBRequest = new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.CadesPayload);

        var baselineBArtifact = service.CreateAttachedSignature(baselineBRequest, material.Certificate, material.Key, material.Suite);
        var timestampMaterial = await CreateTimestampForAttachedSignatureAsync(baselineBArtifact.Data, material.TimestampProvider);
        var baselineTArtifact = service.CreateAttachedSignature(
            baselineBRequest with { Level = SignatureLevel.BaselineT },
            material.Certificate,
            material.Key,
            material.Suite,
            signatureTimestamp: timestampMaterial);
        var verification = service.VerifyAttachedSignature(baselineTArtifact.Data);
        var descriptor = service.ReadSignature(baselineTArtifact.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Equal(SignatureLevel.BaselineT, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.Timestamps);
    }

    [Fact]
    public void XAdES_RuntimeSmoke_ShouldCreateAndVerifyEnvelopedSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var request = new SignatureRequest(SignatureFormat.XAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.XadesPayload);

        var artifact = service.CreateEnvelopedSignature(request, material.Certificate, material.Key, material.Suite);
        var verification = service.VerifyEnvelopedSignature(System.Text.Encoding.UTF8.GetBytes(artifact.XmlDocument));

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Contains("SignedProperties", artifact.XmlDocument);
    }

    [Fact]
    public void JAdES_RuntimeSmoke_ShouldCreateAndVerifyDetachedSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.JadesPayload);

        var envelope = service.CreateDetachedSignature(request, material.Certificate, material.Key, material.Suite);
        var jsonEnvelope = service.CreateDetachedJsonSignature(request, material.Certificate, material.Key, material.Suite);
        var verification = service.VerifyDetachedSignature(request.Payload, envelope.CompactSerialization, material.Certificate);
        using var jsonDocument = JsonDocument.Parse(jsonEnvelope.JsonDocument);
        using var protectedHeader = JsonDocument.Parse(jsonEnvelope.ProtectedHeaderJson);
        var root = jsonDocument.RootElement;
        var protectedRoot = protectedHeader.RootElement;

        var signatures = root.GetProperty("signatures");

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Contains('.', envelope.CompactSerialization);
        Assert.Equal(JsonValueKind.String, root.GetProperty("payload").ValueKind);
        Assert.Equal(JsonValueKind.Array, signatures.ValueKind);
        Assert.Equal(1, signatures.GetArrayLength());
        Assert.Equal(JsonValueKind.String, signatures[0].GetProperty("protected").ValueKind);
        Assert.Equal(JsonValueKind.String, signatures[0].GetProperty("signature").ValueKind);
        Assert.False(root.TryGetProperty("protected", out _));
        Assert.False(root.TryGetProperty("signature", out _));
        Assert.Equal("jose+json", protectedRoot.GetProperty("typ").GetString());
        Assert.True(protectedRoot.GetProperty("x5c").GetArrayLength() > 0);
    }

    [Fact]
    public void PAdES_RuntimeSmoke_ShouldPrepareBindAndVerifySignatureContainer()
    {
        var service = new PAdESBaselineBService();
        var verifier = new PAdESBaselineBVerifier();
        var binding = service.PrepareDetachedSignaturePlaceholder(RuntimeSmokeFixtures.PadesPayload, 512);
        var prepared = service.PrepareDetachedSignatureInput(binding);
        var signed = service.ApplyDetachedSignature(prepared, new byte[] { 0x01, 0x02, 0x03, 0x04 });
        var verification = verifier.Verify(signed);

        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.True(verification.HasDetachedCAdESSignature);
    }

    private static async Task<TimestampMaterial> CreateTimestampForAttachedSignatureAsync(
        ReadOnlyMemory<byte> signature,
        ITimestampProvider timestampProvider)
    {
        var signedCms = new SignedCms();
        signedCms.Decode(signature.ToArray());
        return await CreateTimestampFromSignerInfoAsync(signedCms.SignerInfos[0], timestampProvider);
    }

    private static async Task<TimestampMaterial> CreateTimestampForDetachedSignatureInsideContainerAsync(
        ReadOnlyMemory<byte> containerBytes,
        ReadOnlyMemory<byte> payload,
        ITimestampProvider timestampProvider)
    {
        using var archive = new System.IO.Compression.ZipArchive(new MemoryStream(containerBytes.ToArray()), System.IO.Compression.ZipArchiveMode.Read);
        var signatureEntry = archive.GetEntry("META-INF/signature.p7s")!;
        using var source = signatureEntry.Open();
        using var ms = new MemoryStream();
        await source.CopyToAsync(ms);

        var signedCms = new SignedCms(new ContentInfo(payload.ToArray()), detached: true);
        signedCms.Decode(ms.ToArray());
        return await CreateTimestampFromSignerInfoAsync(signedCms.SignerInfos[0], timestampProvider);
    }

    private static async Task<TimestampMaterial> CreateTimestampFromSignerInfoAsync(
        SignerInfo signerInfo,
        ITimestampProvider timestampProvider)
    {
        var timestampRequest = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signerInfo,
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

    private sealed class RuntimeMaterial : IDisposable
    {
        public RuntimeMaterial()
        {
            var material = TestCertificateFactory.CreateSelfSignedRsa("CN=Runtime Smoke Test");
            var tsaMaterial = TestCertificateFactory.CreateSelfSignedRsaTsa("CN=Runtime Smoke TSA");
            Key = material.Key;
            Certificate = material.Certificate;
            TsaKey = tsaMaterial.Key;
            TsaCertificate = tsaMaterial.Certificate;
            TimestampProvider = new LocalRfc3161TimestampProvider(TsaCertificate);
            Suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
        }

        public RSA Key { get; }
        public X509Certificate2 Certificate { get; }
        public RSA TsaKey { get; }
        public X509Certificate2 TsaCertificate { get; }
        public ITimestampProvider TimestampProvider { get; }
        public SignatureSuite Suite { get; }

        public void Dispose()
        {
            TsaCertificate.Dispose();
            TsaKey.Dispose();
            Certificate.Dispose();
            Key.Dispose();
        }
    }
}
