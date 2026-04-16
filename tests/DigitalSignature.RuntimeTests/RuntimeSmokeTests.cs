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
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

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

        var signingTime = DateTimeOffset.Parse("2026-04-14T08:00:00Z");
        var baselineBArtifact = service.CreateContainer(baselineBRequest, "runtime.txt", material.Certificate, material.Key, material.Suite, signingTime);
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
            signingTime,
            signatureTimestamp: timestampMaterial);
        var verification = service.VerifyContainer(baselineTArtifact.Container.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.NotNull(verification.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineT, verification.Validation.Signature!.Level);
        Assert.Single(verification.Validation.Signature.ValidationMaterial.Timestamps);
    }

    [Fact]
    public async Task ASiC_RuntimeSmoke_ShouldCreateAndVerifyBaselineLTContainer()
    {
        using var material = new RuntimeMaterial();
        var service = new ASiCSBaselineBService();
        var baselineBRequest = new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, RuntimeSmokeFixtures.AsicPayload);

        var signingTime = DateTimeOffset.Parse("2026-04-14T08:01:00Z");
        var baselineBArtifact = service.CreateContainer(baselineBRequest, "runtime-lt.txt", material.Certificate, material.Key, material.Suite, signingTime);
        var timestampMaterial = await CreateTimestampForDetachedSignatureInsideContainerAsync(
            baselineBArtifact.Container.Data,
            baselineBRequest.Payload,
            material.TimestampProvider);

        var baselineLTArtifact = service.CreateContainer(
            baselineBRequest with { Level = SignatureLevel.BaselineLT },
            "runtime-lt.txt",
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            signatureTimestamp: timestampMaterial,
            validationCertificates: [material.Certificate, material.TsaCertificate],
            revocationInfo:
            [
                CreateCrlRevocationInfo(material.Certificate, material.Key, DateTimeOffset.Parse("2026-04-14T08:02:00Z")),
                CreateCrlRevocationInfo(material.TsaCertificate, material.TsaKey, DateTimeOffset.Parse("2026-04-14T08:03:00Z"))
            ]);
        var verification = service.VerifyContainer(baselineLTArtifact.Container.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.NotNull(verification.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineLT, verification.Validation.Signature!.Level);
        Assert.NotEmpty(verification.Validation.Signature.ValidationMaterial.CertificateValues);
        Assert.NotEmpty(verification.Validation.Signature.ValidationMaterial.RevocationValues);
    }

    [Fact]
    public async Task ASiC_RuntimeSmoke_ShouldCreateAndVerifyBaselineLTAContainer()
    {
        using var material = new RuntimeMaterial();
        var service = new ASiCSBaselineBService();
        var baselineBRequest = new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, RuntimeSmokeFixtures.AsicPayload);

        var signingTime = DateTimeOffset.Parse("2026-04-14T08:01:30Z");
        var baselineBArtifact = service.CreateContainer(baselineBRequest, "runtime-lta.txt", material.Certificate, material.Key, material.Suite, signingTime);
        var signatureTimestamp = await CreateTimestampForDetachedSignatureInsideContainerAsync(
            baselineBArtifact.Container.Data,
            baselineBRequest.Payload,
            material.TimestampProvider);

        var baselineLTArtifact = service.CreateContainer(
            baselineBRequest with { Level = SignatureLevel.BaselineLT },
            "runtime-lta.txt",
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            signatureTimestamp,
            [material.Certificate, material.TsaCertificate],
            [
                CreateCrlRevocationInfo(material.Certificate, material.Key, DateTimeOffset.Parse("2026-04-14T08:02:30Z")),
                CreateCrlRevocationInfo(material.TsaCertificate, material.TsaKey, DateTimeOffset.Parse("2026-04-14T08:03:30Z"))
            ]);

        var archiveTimestamp = await CreateArchiveTimestampForContainerAsync(service, baselineLTArtifact.Container.Data, material.Suite.HashAlgorithm, material.TimestampProvider);
        var baselineLtaArtifact = service.AttachArchiveTimestamp(baselineLTArtifact, archiveTimestamp);
        var verification = service.VerifyContainer(baselineLtaArtifact.Container.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.NotNull(verification.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineLTA, verification.Validation.Signature!.Level);
        Assert.Single(verification.Validation.Signature.ValidationMaterial.ArchiveTimestamps);
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

        var signingTime = DateTimeOffset.Parse("2026-04-14T08:05:00Z");
        var baselineBArtifact = service.CreateAttachedSignature(baselineBRequest, material.Certificate, material.Key, material.Suite, signingTime);
        var timestampMaterial = await CreateTimestampForAttachedSignatureAsync(baselineBArtifact.Data, material.TimestampProvider);
        var baselineTArtifact = service.CreateAttachedSignature(
            baselineBRequest with { Level = SignatureLevel.BaselineT },
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            signatureTimestamp: timestampMaterial);
        var verification = service.VerifyAttachedSignature(baselineTArtifact.Data);
        var descriptor = service.ReadSignature(baselineTArtifact.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Equal(SignatureLevel.BaselineT, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.Timestamps);
    }

    [Fact]
    public async Task CAdES_RuntimeSmoke_ShouldCreateAndVerifyAttachedBaselineLTSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new CAdESBaselineBService();
        var baselineBRequest = new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.CadesPayload);

        var signingTime = DateTimeOffset.Parse("2026-04-14T08:06:00Z");
        var baselineBArtifact = service.CreateAttachedSignature(baselineBRequest, material.Certificate, material.Key, material.Suite, signingTime);
        var timestampMaterial = await CreateTimestampForAttachedSignatureAsync(baselineBArtifact.Data, material.TimestampProvider);
        var revocationInfo = CreateCrlRevocationInfo(material.Certificate, material.Key, DateTimeOffset.Parse("2026-04-14T08:07:00Z"));
        var baselineLTArtifact = service.CreateAttachedSignature(
            baselineBRequest with { Level = SignatureLevel.BaselineLT },
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            signatureTimestamp: timestampMaterial,
            validationCertificates: [material.Certificate],
            revocationInfo: [revocationInfo]);
        var verification = service.VerifyAttachedSignature(baselineLTArtifact.Data);
        var descriptor = service.ReadSignature(baselineLTArtifact.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Equal(SignatureLevel.BaselineLT, descriptor.Level);
        Assert.NotEmpty(descriptor.ValidationMaterial.CertificateValues);
        Assert.NotEmpty(descriptor.ValidationMaterial.RevocationValues);
        Assert.Single(descriptor.ValidationMaterial.RevocationInfo);
    }

    [Fact]
    public async Task CAdES_RuntimeSmoke_ShouldCreateAndVerifyAttachedBaselineLTASignature()
    {
        using var material = new RuntimeMaterial();
        var service = new CAdESBaselineBService();
        var baselineBRequest = new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.CadesPayload);

        var signingTime = DateTimeOffset.Parse("2026-04-14T08:06:30Z");
        var baselineBArtifact = service.CreateAttachedSignature(baselineBRequest, material.Certificate, material.Key, material.Suite, signingTime);
        var signatureTimestamp = await CreateTimestampForAttachedSignatureAsync(baselineBArtifact.Data, material.TimestampProvider);
        var baselineLTArtifact = service.CreateAttachedSignature(
            baselineBRequest with { Level = SignatureLevel.BaselineLT },
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            signatureTimestamp,
            [material.Certificate, material.TsaCertificate],
            [
                CreateCrlRevocationInfo(material.Certificate, material.Key, DateTimeOffset.Parse("2026-04-14T08:07:30Z")),
                CreateCrlRevocationInfo(material.TsaCertificate, material.TsaKey, DateTimeOffset.Parse("2026-04-14T08:08:30Z"))
            ]);

        var archiveTimestamp = await CreateArchiveTimestampAsync(service, baselineLTArtifact, material.Suite.HashAlgorithm, material.TimestampProvider);
        var baselineLtaArtifact = service.AttachArchiveTimestamp(baselineLTArtifact, archiveTimestamp);

        var verification = service.VerifyAttachedSignature(baselineLtaArtifact.Data);
        var descriptor = service.ReadSignature(baselineLtaArtifact.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Equal(SignatureLevel.BaselineLTA, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.ArchiveTimestamps);
    }

    [Fact]
    public async Task XAdES_RuntimeSmoke_ShouldCreateAndVerifyBaselineTEnvelopedSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var request = new SignatureRequest(SignatureFormat.XAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.XadesPayload, MimeType: "application/xml");

        var baselineBArtifact = service.CreateEnvelopedSignature(request, material.Certificate, material.Key, material.Suite);
        var timestampResponse = await material.TimestampProvider.GetTimestampAsync(
            service.CreateSignatureTimestampRequest(
                System.Text.Encoding.UTF8.GetBytes(baselineBArtifact.XmlDocument),
                material.Suite.HashAlgorithm));
        var baselineTArtifact = service.AttachSignatureTimestamp(baselineBArtifact, timestampResponse.Timestamp!);
        var verification = service.VerifyEnvelopedSignature(System.Text.Encoding.UTF8.GetBytes(baselineTArtifact.XmlDocument));
        var descriptor = service.ReadSignature(System.Text.Encoding.UTF8.GetBytes(baselineTArtifact.XmlDocument));

        Assert.True(timestampResponse.IsSuccess);
        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Contains("SignedProperties", baselineTArtifact.XmlDocument);
        Assert.Contains("SignatureTimeStamp", baselineTArtifact.XmlDocument);
        Assert.Equal(SignatureLevel.BaselineT, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.Timestamps);
    }

    [Fact]
    public async Task XAdES_RuntimeSmoke_ShouldCreateAndVerifyBaselineLTEnvelopedSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
        var request = new SignatureRequest(SignatureFormat.XAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.XadesPayload, MimeType: "application/xml");

        var baselineBArtifact = service.CreateEnvelopedSignature(request, material.Certificate, material.Key, material.Suite);
        var timestampResponse = await material.TimestampProvider.GetTimestampAsync(
            service.CreateSignatureTimestampRequest(
                System.Text.Encoding.UTF8.GetBytes(baselineBArtifact.XmlDocument),
                material.Suite.HashAlgorithm));
        var baselineTArtifact = service.AttachSignatureTimestamp(baselineBArtifact, timestampResponse.Timestamp!);
        var baselineLTArtifact = service.AttachValidationMaterial(
            baselineTArtifact,
            [material.Certificate, material.TsaCertificate],
            [
                CreateCrlRevocationInfo(material.Certificate, material.Key, DateTimeOffset.Parse("2026-04-14T08:08:00Z")),
                CreateCrlRevocationInfo(material.TsaCertificate, material.TsaKey, DateTimeOffset.Parse("2026-04-14T08:09:00Z"))
            ]);
        var verification = service.VerifyEnvelopedSignature(System.Text.Encoding.UTF8.GetBytes(baselineLTArtifact.XmlDocument));
        var descriptor = service.ReadSignature(System.Text.Encoding.UTF8.GetBytes(baselineLTArtifact.XmlDocument));

        Assert.True(timestampResponse.IsSuccess);
        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Contains("CertificateValues", baselineLTArtifact.XmlDocument);
        Assert.Contains("RevocationValues", baselineLTArtifact.XmlDocument);
        Assert.Equal(SignatureLevel.BaselineLT, descriptor.Level);
        Assert.NotEmpty(descriptor.ValidationMaterial.CertificateValues);
        Assert.NotEmpty(descriptor.ValidationMaterial.RevocationValues);
    }

    [Fact]
    public void JAdES_RuntimeSmoke_ShouldCreateAndVerifyDetachedSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.JadesPayload);

        var envelope = service.CreateDetachedSignature(request, material.Certificate, material.Key, material.Suite);
        var jsonEnvelope = service.CreateDetachedJsonSignature(request, material.Certificate, material.Key, material.Suite);
        var compactVerification = service.VerifyDetachedSignature(request.Payload, envelope.CompactSerialization, material.Certificate);
        var jsonVerification = service.VerifyDetachedJsonSignature(request.Payload, jsonEnvelope.JsonDocument, material.Certificate);
        var descriptor = service.ReadJsonSignature(jsonEnvelope.JsonDocument);
        using var jsonDocument = JsonDocument.Parse(jsonEnvelope.JsonDocument);
        using var protectedHeader = JsonDocument.Parse(jsonEnvelope.ProtectedHeaderJson);
        var root = jsonDocument.RootElement;
        var protectedRoot = protectedHeader.RootElement;

        var signatures = root.GetProperty("signatures");

        Assert.Equal(ValidationConclusion.Valid, compactVerification.Conclusion);
        Assert.Equal(ValidationConclusion.Valid, jsonVerification.Conclusion);
        Assert.Equal(SignatureLevel.BaselineB, descriptor.Level);
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
    public async Task JAdES_RuntimeSmoke_ShouldCreateAndVerifyBaselineTJsonSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.JadesPayload);

        var baselineBEnvelope = service.CreateDetachedJsonSignature(
            request,
            material.Certificate,
            material.Key,
            material.Suite,
            DateTimeOffset.Parse("2026-04-14T08:15:00Z"));
        var timestampResponse = await material.TimestampProvider.GetTimestampAsync(
            service.CreateSignatureTimestampRequest(baselineBEnvelope, material.Suite.HashAlgorithm));
        var baselineTEnvelope = service.AttachSignatureTimestamp(baselineBEnvelope, timestampResponse.Timestamp!);
        var verification = service.VerifyDetachedJsonSignature(request.Payload, baselineTEnvelope.JsonDocument, material.Certificate);
        var descriptor = service.ReadJsonSignature(baselineTEnvelope.JsonDocument);

        Assert.True(timestampResponse.IsSuccess);
        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Equal(SignatureLevel.BaselineT, descriptor.Level);
        Assert.Single(descriptor.ValidationMaterial.Timestamps);
    }

    [Fact]
    public async Task JAdES_RuntimeSmoke_ShouldCreateAndVerifyBaselineLTJsonSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
        var request = new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.JadesPayload);

        var baselineBEnvelope = service.CreateDetachedJsonSignature(
            request,
            material.Certificate,
            material.Key,
            material.Suite,
            DateTimeOffset.Parse("2026-04-14T08:15:00Z"));
        var timestampResponse = await material.TimestampProvider.GetTimestampAsync(
            service.CreateSignatureTimestampRequest(baselineBEnvelope, material.Suite.HashAlgorithm));
        var baselineTEnvelope = service.AttachSignatureTimestamp(baselineBEnvelope, timestampResponse.Timestamp!);
        var baselineLTEnvelope = service.AttachValidationMaterial(
            baselineTEnvelope,
            [material.Certificate, material.TsaCertificate],
            [
                CreateCrlRevocationInfo(material.Certificate, material.Key, DateTimeOffset.Parse("2026-04-14T08:16:00Z")),
                CreateCrlRevocationInfo(material.TsaCertificate, material.TsaKey, DateTimeOffset.Parse("2026-04-14T08:17:00Z"))
            ]);
        var verification = service.VerifyDetachedJsonSignature(request.Payload, baselineLTEnvelope.JsonDocument, material.Certificate);
        var descriptor = service.ReadJsonSignature(baselineLTEnvelope.JsonDocument);

        Assert.True(timestampResponse.IsSuccess);
        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Equal(SignatureLevel.BaselineLT, descriptor.Level);
        Assert.NotEmpty(descriptor.ValidationMaterial.CertificateValues);
        Assert.NotEmpty(descriptor.ValidationMaterial.RevocationValues);
    }

    [Fact]
    public async Task PAdES_RuntimeSmoke_ShouldPrepareBindAndVerifyTimestampedSignatureContainer()
    {
        using var material = new RuntimeMaterial();
        var service = new PAdESBaselineBService();
        var verifier = new PAdESBaselineBVerifier();
        var cadesService = new CAdESBaselineBService();
        var binding = service.PrepareDetachedSignaturePlaceholder(RuntimeSmokeFixtures.PadesPayload, 8192);
        var prepared = service.PrepareDetachedSignatureInput(binding);
        var signingTime = DateTimeOffset.Parse("2026-04-14T08:10:00Z");
        var baselineBSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, prepared.SignedBytes),
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            includeSigningTime: false);
        var baselineTSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineT, prepared.SignedBytes),
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            signatureTimestamp: await CreateTimestampForDetachedCmsAsync(prepared.SignedBytes, baselineBSignature.Data, material.TimestampProvider),
            includeSigningTime: false);
        var signed = service.ApplyDetachedSignature(prepared, baselineTSignature.Data);
        var verification = verifier.Verify(signed);

        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.True(verification.HasDetachedCAdESSignature);
        Assert.NotNull(verification.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineT, verification.Validation.Signature!.Level);
    }

    [Fact]
    public async Task PAdES_RuntimeSmoke_ShouldPrepareBindAndVerifyBaselineLTSignatureContainer()
    {
        using var material = new RuntimeMaterial();
        var service = new PAdESBaselineBService();
        var verifier = new PAdESBaselineBVerifier();
        var cadesService = new CAdESBaselineBService();
        var binding = service.PrepareDetachedSignaturePlaceholder(RuntimeSmokeFixtures.PadesPayload, 8192);
        var prepared = service.PrepareDetachedSignatureInput(binding);
        var signingTime = DateTimeOffset.Parse("2026-04-14T08:11:00Z");
        var baselineBSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, prepared.SignedBytes),
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            includeSigningTime: false);
        var baselineTSignature = cadesService.CreateDetachedSignature(
            new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineT, prepared.SignedBytes),
            material.Certificate,
            material.Key,
            material.Suite,
            signingTime,
            signatureTimestamp: await CreateTimestampForDetachedCmsAsync(prepared.SignedBytes, baselineBSignature.Data, material.TimestampProvider),
            includeSigningTime: false);
        var baselineTPdf = service.ApplyDetachedSignature(prepared, baselineTSignature.Data);
        var baselineLtPdf = service.AugmentToBaselineLT(
            baselineTPdf,
            [
                CreateCrlRevocationInfo(material.Certificate, material.Key, DateTimeOffset.Parse("2026-04-14T08:12:00Z")),
                CreateCrlRevocationInfo(material.TsaCertificate, material.TsaKey, DateTimeOffset.Parse("2026-04-14T08:13:00Z"))
            ],
            [material.Certificate, material.TsaCertificate]);
        var verification = verifier.Verify(baselineLtPdf);

        Assert.Equal(ValidationConclusion.Valid, verification.Validation.Conclusion);
        Assert.True(verification.HasDetachedCAdESSignature);
        Assert.NotNull(verification.Validation.Signature);
        Assert.Equal(SignatureLevel.BaselineLT, verification.Validation.Signature!.Level);
        Assert.NotEmpty(verification.Validation.Signature.ValidationMaterial.CertificateValues);
        Assert.NotEmpty(verification.Validation.Signature.ValidationMaterial.RevocationValues);
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

    private static async Task<TimestampMaterial> CreateTimestampForDetachedCmsAsync(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature,
        ITimestampProvider timestampProvider)
    {
        var signedCms = new SignedCms(new ContentInfo(payload.ToArray()), detached: true);
        signedCms.Decode(signature.ToArray());
        return await CreateTimestampFromSignerInfoAsync(signedCms.SignerInfos[0], timestampProvider);
    }

    private static async Task<TimestampMaterial> CreateArchiveTimestampForContainerAsync(
        ASiCSBaselineBService service,
        ReadOnlyMemory<byte> containerBytes,
        HashAlgorithmIdentifier hashAlgorithm,
        ITimestampProvider timestampProvider)
    {
        var response = await timestampProvider.GetTimestampAsync(
            service.CreateArchiveTimestampRequest(containerBytes, hashAlgorithm));

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.Timestamp);
        return response.Timestamp!;
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

    private static async Task<TimestampMaterial> CreateArchiveTimestampAsync(
        CAdESBaselineBService service,
        SignatureArtifact artifact,
        HashAlgorithmIdentifier hashAlgorithm,
        ITimestampProvider timestampProvider,
        ReadOnlyMemory<byte> detachedPayload = default)
    {
        var response = await timestampProvider.GetTimestampAsync(
            service.CreateArchiveTimestampRequest(artifact.Data, hashAlgorithm, detachedPayload));

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
