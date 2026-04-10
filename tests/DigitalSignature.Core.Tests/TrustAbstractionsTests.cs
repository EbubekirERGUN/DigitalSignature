using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.Core.Tests;

public class TrustAbstractionsTests
{
    [Fact]
    public void TemporalValidationContext_ShouldPreferSigningTime_WhenRequested()
    {
        var signingTime = new DateTimeOffset(2026, 4, 1, 9, 0, 0, TimeSpan.Zero);
        var validationTime = new DateTimeOffset(2026, 4, 10, 9, 0, 0, TimeSpan.Zero);

        var context = TemporalValidationContext.ForSigningTime(validationTime, signingTime);

        Assert.True(context.PreferSigningTime);
        Assert.Equal(signingTime, context.EffectiveValidationTime);
    }

    [Fact]
    public void CertificateChainValidationRequest_Create_ShouldUseEmptyCollectionsByDefault()
    {
        var certificate = new SigningCertificateReference("CN=Signer", "CN=Issuer", "01", "ABC");

        var request = CertificateChainValidationRequest.Create(certificate, DateTimeOffset.UtcNow, useSigningTime: true);

        Assert.Empty(request.IntermediateCertificates);
        Assert.Empty(request.TrustAnchors);
        Assert.Empty(request.RevocationEvidence);
        Assert.True(request.UseSigningTime);
    }

    [Fact]
    public void CertificateChainValidationResult_Success_ShouldPreserveChainAndAnchor()
    {
        var chain = new[]
        {
            new SigningCertificateReference("CN=Signer", "CN=Issuer", "01", "ABC")
        };
        var anchor = new CertificateTrustAnchor("CN=Root", "ROOT", ReadOnlyMemory<byte>.Empty, "test");

        var result = CertificateChainValidationResult.Success(chain, anchor);

        Assert.True(result.IsTrusted);
        Assert.Single(result.Chain);
        Assert.Equal(anchor, result.TrustAnchor);
        Assert.Empty(result.Failures);
    }

    [Fact]
    public void RevocationEvidence_ShouldModelOcspAndCrlSources()
    {
        var ocspEvidence = new CertificateRevocationEvidence(
            CertificateRevocationSource.Ocsp,
            CertificateRevocationStatus.Good,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(1),
            null,
            "Responder");

        var crlEvidence = new CertificateRevocationEvidence(
            CertificateRevocationSource.Crl,
            CertificateRevocationStatus.Revoked,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            DateTimeOffset.UtcNow.AddHours(-1),
            Reason: "KeyCompromise");

        Assert.Equal(CertificateRevocationSource.Ocsp, ocspEvidence.Source);
        Assert.Equal(CertificateRevocationStatus.Good, ocspEvidence.Status);
        Assert.Equal(CertificateRevocationSource.Crl, crlEvidence.Source);
        Assert.Equal(CertificateRevocationStatus.Revoked, crlEvidence.Status);
    }

    [Fact]
    public void TrustContracts_ShouldBeResolvableFromCoreAssembly()
    {
        Assert.Equal("DigitalSignature.Core", typeof(ITrustAnchorProvider).Namespace);
        Assert.Equal("DigitalSignature.Core", typeof(IOcspResponder).Namespace);
        Assert.Equal("DigitalSignature.Core", typeof(ICrlProvider).Namespace);
        Assert.Equal("DigitalSignature.Core", typeof(ICertificateChainValidator).Namespace);
    }
}
