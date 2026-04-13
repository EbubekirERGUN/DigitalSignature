using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;

namespace DigitalSignature.Core.Tests;

public class SignatureAugmentationEngineTests
{
    [Fact]
    public async Task AugmentAsync_ShouldRaiseCAdESBaselineB_ToBaselineT()
    {
        var engine = new SignatureAugmentationEngine([new CAdESAugmenter()]);
        var signature = CreateSignature(SignatureLevel.BaselineB);
        var timestamp = new TimestampMaterial("timestamp-token"u8.ToArray(), DateTimeOffset.UtcNow, HashAlgorithm: "SHA-256");
        var request = new AugmentationRequest(
            signature,
            SignatureLevel.BaselineT,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, signature.SigningTime),
            Timestamps: [timestamp]);

        var result = await engine.AugmentAsync(request);

        Assert.Equal(SignatureLevel.BaselineT, result.Signature.Level);
        Assert.Single(result.Signature.ValidationMaterial.Timestamps);
        Assert.Single(result.TimestampPlan.Attachments);
    }

    [Fact]
    public async Task AugmentAsync_ShouldRaiseCAdESBaselineT_ToBaselineLT_AndEmbedRevocationInfo()
    {
        var engine = new SignatureAugmentationEngine([new CAdESAugmenter()]);
        var timestamp = new TimestampMaterial("timestamp-token"u8.ToArray(), DateTimeOffset.UtcNow, HashAlgorithm: "SHA-256");
        var signature = CreateSignature(SignatureLevel.BaselineT) with
        {
            ValidationMaterial = ValidationMaterial.Empty with { Timestamps = [timestamp] }
        };

        var revocationInfo = new RevocationInfo("OCSP", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), false, null, null);
        var request = new AugmentationRequest(
            signature,
            SignatureLevel.BaselineLT,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, signature.SigningTime),
            RevocationInfo: [revocationInfo],
            Timestamps: [timestamp]);

        var result = await engine.AugmentAsync(request);

        Assert.Equal(SignatureLevel.BaselineLT, result.Signature.Level);
        Assert.Single(result.Signature.ValidationMaterial.RevocationInfo);
        Assert.True(result.HasEmbeddedValidationData);
    }

    [Fact]
    public async Task AugmentAsync_ShouldRaiseCAdESBaselineLT_ToBaselineLTA_AndEmbedArchiveEvidence()
    {
        var engine = new SignatureAugmentationEngine([new CAdESAugmenter()]);
        var signature = CreateSignature(SignatureLevel.BaselineLT) with
        {
            ValidationMaterial = ValidationMaterial.Empty with
            {
                Timestamps = [new TimestampMaterial("timestamp-token"u8.ToArray(), DateTimeOffset.UtcNow)],
                RevocationInfo = [new RevocationInfo("CRL", DateTimeOffset.UtcNow, null, false, null, null)]
            }
        };

        var request = new AugmentationRequest(
            signature,
            SignatureLevel.BaselineLTA,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, signature.SigningTime),
            Timestamps: signature.ValidationMaterial.Timestamps,
            EvidenceRecords: ["archive-evidence"u8.ToArray()]);

        var result = await engine.AugmentAsync(request);

        Assert.Equal(SignatureLevel.BaselineLTA, result.Signature.Level);
        Assert.Single(result.Signature.ValidationMaterial.EvidenceRecords);
        Assert.True(result.HasArchiveEvidence);
    }

    private static SignatureDescriptor CreateSignature(SignatureLevel level)
        => new(
            SignatureFormat.CAdES,
            level,
            new SigningCertificateReference("CN=Signer", "CN=Issuer", "01", "thumbprint", DateTimeOffset.UtcNow.AddDays(-1).ToString("O"), DateTimeOffset.UtcNow.AddYears(1).ToString("O")),
            DateTimeOffset.UtcNow,
            ValidationMaterial.Empty);
}
