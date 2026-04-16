using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

var outputDirectory = Path.GetFullPath(args.Length > 0 ? args[0] : Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "artifacts", "runtime-demo"));
var utf8WithoutBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
Directory.CreateDirectory(outputDirectory);

var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
var demoCertificateNotBefore = DateTimeOffset.Parse("2025-01-01T00:00:00Z");
var demoCertificateNotAfter = DateTimeOffset.Parse("2030-01-01T00:00:00Z");
using var rsa = RSA.Create(2048);
using var certificate = CreateSigningCertificate(rsa, "CN=DigitalSignature Runtime Demo");
using var tsaKey = RSA.Create(2048);
using var tsaCertificate = CreateTsaCertificate(tsaKey, "CN=DigitalSignature Runtime TSA");
var timestampProvider = new LocalRfc3161TimestampProvider(tsaCertificate);

var cadesPayload = Encoding.UTF8.GetBytes("Runtime CAdES payload");
var asicPayload = Encoding.UTF8.GetBytes("Runtime ASiC payload");
var xadesPayload = Encoding.UTF8.GetBytes("<Invoice Id=\"inv-42\"><Total Currency=\"TRY\">123.45</Total></Invoice>");
var jadesPayload = Encoding.UTF8.GetBytes("{\"invoice\":{\"id\":42,\"currency\":\"TRY\"},\"total\":123.45}");
var padesPayload = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF");

var asicSigningTime = DateTimeOffset.Parse("2026-04-14T08:00:00Z");
var cadesSigningTime = DateTimeOffset.Parse("2026-04-14T08:05:00Z");
var padesSigningTime = DateTimeOffset.Parse("2026-04-14T08:10:00Z");

var asicService = new ASiCSBaselineBService();
var asicArtifact = asicService.CreateContainer(new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineB, asicPayload), "sample-asic.txt", certificate, rsa, suite, asicSigningTime);
var asicVerification = asicService.VerifyContainer(asicArtifact.Container.Data);
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-asic.asics"), asicArtifact.Container.Data.ToArray());

var cadesService = new CAdESBaselineBService();
var cadesArtifact = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, cadesPayload), certificate, rsa, suite);
var cadesVerification = cadesService.VerifyDetachedSignature(cadesPayload, cadesArtifact.Data);
var cadesAttachedArtifact = cadesService.CreateAttachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, cadesPayload), certificate, rsa, suite, cadesSigningTime);
var cadesAttachedVerification = cadesService.VerifyAttachedSignature(cadesAttachedArtifact.Data);
var cadesTimestampMaterial = await CreateTimestampForAttachedSignatureAsync(cadesAttachedArtifact.Data, timestampProvider);
var cadesBaselineTArtifact = cadesService.CreateAttachedSignature(
    new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineT, cadesPayload),
    certificate,
    rsa,
    suite,
    cadesSigningTime,
    signatureTimestamp: cadesTimestampMaterial);
var cadesBaselineTVerification = cadesService.VerifyAttachedSignature(cadesBaselineTArtifact.Data);
var cadesBaselineLTArtifact = cadesService.CreateAttachedSignature(
    new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineLT, cadesPayload),
    certificate,
    rsa,
    suite,
    cadesSigningTime,
    signatureTimestamp: cadesTimestampMaterial,
    validationCertificates: [certificate],
    revocationInfo: [CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-14T08:06:00Z"))]);
var cadesBaselineLTVerification = cadesService.VerifyAttachedSignature(cadesBaselineLTArtifact.Data);
var cadesArchiveTimestamp = await CreateArchiveTimestampAsync(cadesService, cadesBaselineLTArtifact, suite.HashAlgorithm, timestampProvider);
var cadesBaselineLTAArtifact = cadesService.AttachArchiveTimestamp(cadesBaselineLTArtifact, cadesArchiveTimestamp);
var cadesBaselineLTAVerification = cadesService.VerifyAttachedSignature(cadesBaselineLTAArtifact.Data);
var asicBaselineTArtifact = asicService.CreateContainer(
    new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineT, asicPayload),
    "sample-asic-t.txt",
    certificate,
    rsa,
    suite,
    asicSigningTime,
    signatureTimestamp: await CreateTimestampForDetachedSignatureAsync(cadesService, certificate, rsa, suite, asicPayload, timestampProvider, asicSigningTime));
var asicBaselineTVerification = asicService.VerifyContainer(asicBaselineTArtifact.Container.Data);
var asicBaselineLTArtifact = asicService.CreateContainer(
    new SignatureRequest(SignatureFormat.ASiC, SignatureLevel.BaselineLT, asicPayload),
    "sample-asic-lt.txt",
    certificate,
    rsa,
    suite,
    asicSigningTime,
    signatureTimestamp: await CreateTimestampForDetachedSignatureAsync(cadesService, certificate, rsa, suite, asicPayload, timestampProvider, asicSigningTime),
    validationCertificates: [certificate, tsaCertificate],
    revocationInfo:
    [
        CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-14T08:01:00Z")),
        CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.Parse("2026-04-14T08:02:00Z"))
    ]);
var asicBaselineLTVerification = asicService.VerifyContainer(asicBaselineLTArtifact.Container.Data);
var asicArchiveTimestamp = await CreateArchiveTimestampForContainerAsync(asicService, asicBaselineLTArtifact.Container.Data, suite.HashAlgorithm, timestampProvider);
var asicBaselineLTAArtifact = asicService.AttachArchiveTimestamp(asicBaselineLTArtifact, asicArchiveTimestamp);
var asicBaselineLTAVerification = asicService.VerifyContainer(asicBaselineLTAArtifact.Container.Data);
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-cades.p7s"), cadesArtifact.Data.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-cades.p7m"), cadesAttachedArtifact.Data.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-cades-t.p7m"), cadesBaselineTArtifact.Data.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-cades-lt.p7m"), cadesBaselineLTArtifact.Data.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-cades-lta.p7m"), cadesBaselineLTAArtifact.Data.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-cades-payload.bin"), cadesPayload);
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-asic-t.asics"), asicBaselineTArtifact.Container.Data.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-asic-lt.asics"), asicBaselineLTArtifact.Container.Data.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-asic-lta.asics"), asicBaselineLTAArtifact.Container.Data.ToArray());

var xadesService = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
var xadesArtifact = xadesService.CreateEnvelopedSignature(new SignatureRequest(SignatureFormat.XAdES, SignatureLevel.BaselineB, xadesPayload, MimeType: "application/xml"), certificate, rsa, suite);
var xadesVerification = xadesService.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(xadesArtifact.XmlDocument));
var xadesTimestampResponse = await timestampProvider.GetTimestampAsync(
    xadesService.CreateSignatureTimestampRequest(
        Encoding.UTF8.GetBytes(xadesArtifact.XmlDocument),
        suite.HashAlgorithm));
if (!xadesTimestampResponse.IsSuccess || xadesTimestampResponse.Timestamp is null)
{
    throw new InvalidOperationException(xadesTimestampResponse.FailureMessage ?? "Failed to create XAdES timestamp token.");
}

var xadesBaselineTArtifact = xadesService.AttachSignatureTimestamp(xadesArtifact, xadesTimestampResponse.Timestamp);
var xadesBaselineTVerification = xadesService.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(xadesBaselineTArtifact.XmlDocument));
var xadesBaselineLTArtifact = xadesService.AttachValidationMaterial(
    xadesBaselineTArtifact,
    [certificate, tsaCertificate],
    [
        CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-14T08:08:00Z")),
        CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.Parse("2026-04-14T08:09:00Z"))
    ]);
var xadesBaselineLTVerification = xadesService.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(xadesBaselineLTArtifact.XmlDocument));
var xadesArchiveTimestampResponse = await timestampProvider.GetTimestampAsync(
    xadesService.CreateArchiveTimestampRequest(
        Encoding.UTF8.GetBytes(xadesBaselineLTArtifact.XmlDocument),
        suite.HashAlgorithm));
if (!xadesArchiveTimestampResponse.IsSuccess || xadesArchiveTimestampResponse.Timestamp is null)
{
    throw new InvalidOperationException(xadesArchiveTimestampResponse.FailureMessage ?? "Failed to create XAdES archive timestamp token.");
}
var xadesBaselineLTAArtifact = xadesService.AttachArchiveTimestamp(xadesBaselineLTArtifact, xadesArchiveTimestampResponse.Timestamp);
var xadesBaselineLTAVerification = xadesService.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(xadesBaselineLTAArtifact.XmlDocument));
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-xades.xml"), xadesArtifact.XmlDocument, utf8WithoutBom);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-xades-t.xml"), xadesBaselineTArtifact.XmlDocument, utf8WithoutBom);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-xades-lt.xml"), xadesBaselineLTArtifact.XmlDocument, utf8WithoutBom);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-xades-lta.xml"), xadesBaselineLTAArtifact.XmlDocument, utf8WithoutBom);

var jadesService = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
var jadesSigningTime = DateTimeOffset.Parse("2026-04-14T08:15:00Z");
var jadesArtifact = jadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, jadesPayload), certificate, rsa, suite, jadesSigningTime);
var jadesJsonArtifact = jadesService.CreateDetachedJsonSignature(new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, jadesPayload), certificate, rsa, suite, jadesSigningTime);
var jadesVerification = jadesService.VerifyDetachedSignature(jadesPayload, jadesArtifact.CompactSerialization, certificate);
var jadesJsonVerification = jadesService.VerifyDetachedJsonSignature(jadesPayload, jadesJsonArtifact.JsonDocument, certificate);
var jadesTimestampResponse = await timestampProvider.GetTimestampAsync(
    jadesService.CreateSignatureTimestampRequest(jadesJsonArtifact, suite.HashAlgorithm));
if (!jadesTimestampResponse.IsSuccess || jadesTimestampResponse.Timestamp is null)
{
    throw new InvalidOperationException(jadesTimestampResponse.FailureMessage ?? "Failed to create JAdES timestamp token.");
}

var jadesBaselineTArtifact = jadesService.AttachSignatureTimestamp(jadesJsonArtifact, jadesTimestampResponse.Timestamp);
var jadesBaselineTVerification = jadesService.VerifyDetachedJsonSignature(jadesPayload, jadesBaselineTArtifact.JsonDocument, certificate);
var jadesBaselineLTArtifact = jadesService.AttachValidationMaterial(
    jadesBaselineTArtifact,
    [certificate, tsaCertificate],
    [
        CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-14T08:16:00Z")),
        CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.Parse("2026-04-14T08:17:00Z"))
    ]);
var jadesBaselineLTVerification = jadesService.VerifyDetachedJsonSignature(jadesPayload, jadesBaselineLTArtifact.JsonDocument, certificate);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-jades.jws"), jadesArtifact.CompactSerialization, Encoding.ASCII);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-jades.json"), jadesJsonArtifact.JsonDocument, utf8WithoutBom);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-jades-t.json"), jadesBaselineTArtifact.JsonDocument, utf8WithoutBom);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-jades-lt.json"), jadesBaselineLTArtifact.JsonDocument, utf8WithoutBom);
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-jades-payload.json"), jadesPayload);

var padesService = new PAdESBaselineBService();
var padesVerifier = new PAdESBaselineBVerifier();
var padesBinding = padesService.PrepareDetachedSignaturePlaceholder(padesPayload, 4096);
var padesInput = padesService.PrepareDetachedSignatureInput(padesBinding);
var padesCms = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, padesInput.SignedBytes), certificate, rsa, suite, includeSigningTime: false);
var padesDocument = padesService.ApplyDetachedSignature(padesInput, padesCms.Data);
var padesVerification = padesVerifier.Verify(padesDocument);
var padesTBinding = padesService.PrepareDetachedSignaturePlaceholder(padesPayload, 8192);
var padesTInput = padesService.PrepareDetachedSignatureInput(padesTBinding);
var padesTCadesBaselineB = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, padesTInput.SignedBytes), certificate, rsa, suite, padesSigningTime, includeSigningTime: false);
var padesTTimestamp = await CreateTimestampForDetachedCmsBytesAsync(padesTInput.SignedBytes, padesTCadesBaselineB.Data, timestampProvider);
var padesTCms = cadesService.CreateDetachedSignature(
    new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineT, padesTInput.SignedBytes),
    certificate,
    rsa,
    suite,
    padesSigningTime,
    signatureTimestamp: padesTTimestamp,
    includeSigningTime: false);
var padesTDocument = padesService.ApplyDetachedSignature(padesTInput, padesTCms.Data);
var padesTVerification = padesVerifier.Verify(padesTDocument);
var padesLtDocument = padesService.AugmentToBaselineLT(
    padesTDocument,
    [
        CreateCrlRevocationInfo(certificate, rsa, DateTimeOffset.Parse("2026-04-14T08:12:00Z")),
        CreateCrlRevocationInfo(tsaCertificate, tsaKey, DateTimeOffset.Parse("2026-04-14T08:13:00Z"))
    ],
    [certificate, tsaCertificate]);
var padesLtVerification = padesVerifier.Verify(padesLtDocument);
var padesLtaInput = padesService.PrepareDocumentTimestampInput(padesLtDocument, 8192);
var padesLtaTimestampResponse = await timestampProvider.GetTimestampAsync(
    padesService.CreateDocumentTimestampRequest(padesLtaInput, suite.HashAlgorithm));
if (!padesLtaTimestampResponse.IsSuccess || padesLtaTimestampResponse.Timestamp is null)
{
    throw new InvalidOperationException(padesLtaTimestampResponse.FailureMessage ?? "Failed to create PAdES document timestamp token.");
}
var padesLtaDocument = padesService.ApplyDocumentTimestamp(padesLtaInput, padesLtaTimestampResponse.Timestamp);
var padesLtaVerification = padesVerifier.Verify(padesLtaDocument);
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-pades.pdf"), padesDocument.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-pades-t.pdf"), padesTDocument.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-pades-lt.pdf"), padesLtDocument.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-pades-lta.pdf"), padesLtaDocument.ToArray());

await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "demo-cert.cer"), certificate.Export(X509ContentType.Cert));
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "demo-tsa-cert.cer"), tsaCertificate.Export(X509ContentType.Cert));

var summary = $"""
Runtime artifact demo output: {outputDirectory}

ASiC verification: {asicVerification.Validation.Conclusion}
ASiC-T verification: {asicBaselineTVerification.Validation.Conclusion}
ASiC-LT verification: {asicBaselineLTVerification.Validation.Conclusion} ({asicBaselineLTVerification.Validation.Signature?.Level})
ASiC-LTA verification: {asicBaselineLTAVerification.Validation.Conclusion} ({asicBaselineLTAVerification.Validation.Signature?.Level})
CAdES detached verification: {cadesVerification.Conclusion}
CAdES attached verification: {cadesAttachedVerification.Conclusion}
CAdES-T attached verification: {cadesBaselineTVerification.Conclusion}
CAdES-LT attached verification: {cadesBaselineLTVerification.Conclusion}
CAdES-LTA attached verification: {cadesBaselineLTAVerification.Conclusion} ({cadesService.ReadSignature(cadesBaselineLTAArtifact.Data).Level})
XAdES verification: {xadesVerification.Conclusion}
XAdES-T verification: {xadesBaselineTVerification.Conclusion}
XAdES-LT verification: {xadesBaselineLTVerification.Conclusion}
XAdES-LTA verification: {xadesBaselineLTAVerification.Conclusion} ({xadesService.ReadSignature(Encoding.UTF8.GetBytes(xadesBaselineLTAArtifact.XmlDocument)).Level})
JAdES compact verification: {jadesVerification.Conclusion}
JAdES JSON verification: {jadesJsonVerification.Conclusion}
JAdES-T verification: {jadesBaselineTVerification.Conclusion} ({jadesService.ReadJsonSignature(jadesBaselineTArtifact.JsonDocument).Level})
JAdES-LT verification: {jadesBaselineLTVerification.Conclusion} ({jadesService.ReadJsonSignature(jadesBaselineLTArtifact.JsonDocument).Level})
PAdES verification: {padesVerification.Validation.Conclusion}
PAdES-T verification: {padesTVerification.Validation.Conclusion} ({padesTVerification.Validation.Signature?.Level})
PAdES-LT verification: {padesLtVerification.Validation.Conclusion} ({padesLtVerification.Validation.Signature?.Level})
PAdES-LTA verification: {padesLtaVerification.Validation.Conclusion} ({padesLtaVerification.Validation.Signature?.Level})

Files:
- sample-asic.asics
- sample-asic-t.asics
- sample-asic-lt.asics
- sample-asic-lta.asics
- sample-cades.p7s
- sample-cades.p7m
- sample-cades-t.p7m
- sample-cades-lt.p7m
- sample-cades-lta.p7m
- sample-cades-payload.bin
- sample-xades.xml
- sample-xades-t.xml
- sample-xades-lt.xml
- sample-xades-lta.xml
- sample-jades.jws
- sample-jades.json
- sample-jades-t.json
- sample-jades-lt.json
- sample-jades-payload.json
- sample-pades.pdf
- sample-pades-t.pdf
- sample-pades-lt.pdf
- sample-pades-lta.pdf
- demo-cert.cer
- demo-tsa-cert.cer
""";

Console.WriteLine(summary);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "README.txt"), summary, utf8WithoutBom);

static RevocationInfo CreateCrlRevocationInfo(
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

static async Task<TimestampMaterial> CreateTimestampForAttachedSignatureAsync(
    ReadOnlyMemory<byte> signature,
    ITimestampProvider timestampProvider)
{
    var signedCms = new SignedCms();
    signedCms.Decode(signature.ToArray());
    return await CreateTimestampFromSignerInfoAsync(signedCms.SignerInfos[0], timestampProvider);
}

static async Task<TimestampMaterial> CreateTimestampForDetachedSignatureAsync(
    CAdESBaselineBService cadesService,
    X509Certificate2 certificate,
    RSA rsa,
    SignatureSuite suite,
    ReadOnlyMemory<byte> payload,
    ITimestampProvider timestampProvider,
    DateTimeOffset signingTime)
{
    var artifact = cadesService.CreateDetachedSignature(
        new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, payload),
        certificate,
        rsa,
        suite,
        signingTime);

    return await CreateTimestampForDetachedCmsBytesAsync(payload, artifact.Data, timestampProvider);
}

static async Task<TimestampMaterial> CreateTimestampForDetachedCmsBytesAsync(
    ReadOnlyMemory<byte> payload,
    ReadOnlyMemory<byte> signature,
    ITimestampProvider timestampProvider)
{
    var signedCms = new SignedCms(new ContentInfo(payload.ToArray()), detached: true);
    signedCms.Decode(signature.ToArray());
    return await CreateTimestampFromSignerInfoAsync(signedCms.SignerInfos[0], timestampProvider);
}

static async Task<TimestampMaterial> CreateArchiveTimestampForContainerAsync(
    ASiCSBaselineBService asicService,
    ReadOnlyMemory<byte> containerBytes,
    HashAlgorithmIdentifier hashAlgorithm,
    ITimestampProvider timestampProvider)
{
    var response = await timestampProvider.GetTimestampAsync(
        asicService.CreateArchiveTimestampRequest(containerBytes, hashAlgorithm));

    if (!response.IsSuccess || response.Timestamp is null)
    {
        throw new InvalidOperationException(response.FailureMessage ?? "Failed to create ASiC archive timestamp token.");
    }

    return response.Timestamp;
}

static async Task<TimestampMaterial> CreateArchiveTimestampAsync(
    CAdESBaselineBService cadesService,
    SignatureArtifact artifact,
    HashAlgorithmIdentifier hashAlgorithm,
    ITimestampProvider timestampProvider,
    ReadOnlyMemory<byte> detachedPayload = default)
{
    var response = await timestampProvider.GetTimestampAsync(
        cadesService.CreateArchiveTimestampRequest(artifact.Data, hashAlgorithm, detachedPayload));

    if (!response.IsSuccess || response.Timestamp is null)
    {
        throw new InvalidOperationException(response.FailureMessage ?? "Failed to create archive timestamp token.");
    }

    return response.Timestamp;
}

static async Task<TimestampMaterial> CreateTimestampFromSignerInfoAsync(
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

    if (!response.IsSuccess || response.Timestamp is null)
    {
        throw new InvalidOperationException(response.FailureMessage ?? "Failed to create RFC 3161 timestamp token.");
    }

    return response.Timestamp;
}

X509Certificate2 CreateSigningCertificate(RSA rsa, string subjectName)
{
    var certificateRequest = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));
    certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
    return certificateRequest.CreateSelfSigned(demoCertificateNotBefore, demoCertificateNotAfter);
}

X509Certificate2 CreateTsaCertificate(RSA rsa, string subjectName)
{
    var certificateRequest = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));
    certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));

    var enhancedKeyUsages = new OidCollection { new("1.3.6.1.5.5.7.3.8") };
    certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, true));
    return certificateRequest.CreateSelfSigned(demoCertificateNotBefore, demoCertificateNotAfter);
}
