using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using DigitalSignature.JAdES;
using DigitalSignature.PAdES;
using DigitalSignature.XAdES;

var outputDirectory = Path.GetFullPath(args.Length > 0 ? args[0] : Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "artifacts", "runtime-demo"));
Directory.CreateDirectory(outputDirectory);

var suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
using var rsa = RSA.Create(2048);
var certificateRequest = new CertificateRequest("CN=DigitalSignature Runtime Demo", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));
certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

var cadesPayload = Encoding.UTF8.GetBytes("Runtime CAdES payload");
var xadesPayload = Encoding.UTF8.GetBytes("<Invoice Id=\"inv-42\"><Total Currency=\"TRY\">123.45</Total></Invoice>");
var jadesPayload = Encoding.UTF8.GetBytes("{\"invoice\":{\"id\":42,\"currency\":\"TRY\"},\"total\":123.45}");
var padesPayload = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF");

var cadesService = new CAdESBaselineBService();
var cadesArtifact = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, cadesPayload), certificate, rsa, suite);
var cadesVerification = cadesService.VerifyDetachedSignature(cadesPayload, cadesArtifact.Data);
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-cades.p7s"), cadesArtifact.Data.ToArray());
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-cades-payload.bin"), cadesPayload);

var xadesService = new XAdESBaselineBService(new ExclusiveXmlCanonicalizer());
var xadesArtifact = xadesService.CreateEnvelopedSignature(new SignatureRequest(SignatureFormat.XAdES, SignatureLevel.BaselineB, xadesPayload), certificate, rsa, suite);
var xadesVerification = xadesService.VerifyEnvelopedSignature(Encoding.UTF8.GetBytes(xadesArtifact.XmlDocument));
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-xades.xml"), xadesArtifact.XmlDocument, Encoding.UTF8);

var jadesService = new JAdESBaselineBService(new Rfc8785JsonCanonicalizer());
var jadesArtifact = jadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.JAdES, SignatureLevel.BaselineB, jadesPayload), certificate, rsa, suite);
var jadesVerification = jadesService.VerifyDetachedSignature(jadesPayload, jadesArtifact.CompactSerialization, certificate);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "sample-jades.jws"), jadesArtifact.CompactSerialization, Encoding.ASCII);
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-jades-payload.json"), jadesPayload);

var padesService = new PAdESBaselineBService();
var padesBinding = padesService.PrepareDetachedSignaturePlaceholder(padesPayload, 4096);
var padesInput = padesService.PrepareDetachedSignatureInput(padesBinding);
var padesCms = cadesService.CreateDetachedSignature(new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, padesInput.SignedBytes), certificate, rsa, suite);
var padesDocument = padesService.ApplyDetachedSignature(padesInput, padesCms.Data);
await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "sample-pades.pdf"), padesDocument.ToArray());

await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "demo-cert.cer"), certificate.Export(X509ContentType.Cert));

var summary = $"""
Runtime artifact demo output: {outputDirectory}

CAdES verification: {cadesVerification.Conclusion}
XAdES verification: {xadesVerification.Conclusion}
JAdES verification: {jadesVerification.Conclusion}
PAdES output: created (container-level binding)

Files:
- sample-cades.p7s
- sample-cades-payload.bin
- sample-xades.xml
- sample-jades.jws
- sample-jades-payload.json
- sample-pades.pdf
- demo-cert.cer
""";

Console.WriteLine(summary);
await File.WriteAllTextAsync(Path.Combine(outputDirectory, "README.txt"), summary, Encoding.UTF8);
