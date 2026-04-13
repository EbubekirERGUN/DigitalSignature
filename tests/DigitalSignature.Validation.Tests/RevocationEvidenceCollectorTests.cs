using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using DigitalSignature.Validation;

namespace DigitalSignature.Validation.Tests;

public class RevocationEvidenceCollectorTests
{
    [Fact]
    public async Task CollectAsync_ShouldCombineOcspAndCrlEvidence()
    {
        var collector = new RevocationEvidenceCollector(
            new StubOcspResponder(_ => new CertificateRevocationEvidence(
                CertificateRevocationSource.Ocsp,
                CertificateRevocationStatus.Good,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddHours(1),
                null,
                "ocsp-responder")),
            new StubCrlProvider(_ =>
            [
                new CertificateRevocationEvidence(
                    CertificateRevocationSource.Crl,
                    CertificateRevocationStatus.Unknown,
                    DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow.AddHours(-1),
                    DateTimeOffset.UtcNow.AddHours(12),
                    null,
                    "crl-issuer")
            ]));

        var result = await collector.CollectAsync(
            new SigningCertificateReference("CN=Signer", "CN=Issuer", "01", "ABC"),
            new SigningCertificateReference("CN=Issuer", "CN=Root", "02", "DEF"),
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        Assert.Equal(2, result.Count);
        Assert.Contains(result, evidence => evidence.Source == CertificateRevocationSource.Ocsp);
        Assert.Contains(result, evidence => evidence.Source == CertificateRevocationSource.Crl);
    }

    private sealed class StubOcspResponder(Func<(SigningCertificateReference certificate, SigningCertificateReference? issuer, TemporalValidationContext context), CertificateRevocationEvidence?> callback) : IOcspResponder
    {
        public ValueTask<CertificateRevocationEvidence?> GetRevocationEvidenceAsync(SigningCertificateReference certificate, SigningCertificateReference? issuer, TemporalValidationContext temporalContext, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(callback((certificate, issuer, temporalContext)));
    }

    private sealed class StubCrlProvider(Func<(SigningCertificateReference certificate, SigningCertificateReference? issuer, TemporalValidationContext context), IReadOnlyList<CertificateRevocationEvidence>> callback) : ICrlProvider
    {
        public ValueTask<IReadOnlyList<CertificateRevocationEvidence>> GetRevocationEvidenceAsync(SigningCertificateReference certificate, SigningCertificateReference? issuer, TemporalValidationContext temporalContext, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(callback((certificate, issuer, temporalContext)));
    }
}
