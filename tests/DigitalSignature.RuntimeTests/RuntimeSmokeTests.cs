using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;
using DigitalSignature.JAdES;
using DigitalSignature.PAdES;
using DigitalSignature.XAdES;

namespace DigitalSignature.RuntimeTests;

public class RuntimeSmokeTests
{
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
    public void CAdES_RuntimeSmoke_ShouldCreateAndVerifyAttachedSignature()
    {
        using var material = new RuntimeMaterial();
        var service = new CAdESBaselineBService();
        var request = new SignatureRequest(SignatureFormat.CAdES, SignatureLevel.BaselineB, RuntimeSmokeFixtures.CadesPayload);

        var artifact = service.CreateAttachedSignature(request, material.Certificate, material.Key, material.Suite);
        var verification = service.VerifyAttachedSignature(artifact.Data);

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.NotEmpty(artifact.Data.ToArray());
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
        var verification = service.VerifyDetachedSignature(request.Payload, envelope.CompactSerialization, material.Certificate);

        Assert.Equal(ValidationConclusion.Valid, verification.Conclusion);
        Assert.Contains('.', envelope.CompactSerialization);
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

    private sealed class RuntimeMaterial : IDisposable
    {
        public RuntimeMaterial()
        {
            var material = TestCertificateFactory.CreateSelfSignedRsa("CN=Runtime Smoke Test");
            Key = material.Key;
            Certificate = material.Certificate;
            Suite = new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true);
        }

        public System.Security.Cryptography.RSA Key { get; }
        public System.Security.Cryptography.X509Certificates.X509Certificate2 Certificate { get; }
        public SignatureSuite Suite { get; }

        public void Dispose()
        {
            Certificate.Dispose();
            Key.Dispose();
        }
    }
}
