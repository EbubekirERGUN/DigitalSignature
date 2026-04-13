using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;

namespace DigitalSignature.CAdES.Tests;

public class CAdESTimestampIntegrationTests
{
    [Fact]
    public void PlanBaselineT_ShouldPrepareSingleTimestampAttachment()
    {
        var signingCertificate = new SigningCertificateReference("CN=Signer", "CN=Issuer", "01", "ABC");
        var signature = new SignatureDescriptor(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            signingCertificate,
            DateTimeOffset.UtcNow,
            new ValidationMaterial(signingCertificate, [signingCertificate], [], [], []));
        var timestamp = new TimestampMaterial("token"u8.ToArray(), DateTimeOffset.UtcNow, "1.2.3.4", "SHA-256");

        var plan = CAdESTimestampIntegration.PlanBaselineT(signature, timestamp);

        Assert.Equal(SignatureFormat.CAdES, plan.Format);
        Assert.Equal(SignatureLevel.BaselineB, plan.CurrentLevel);
        Assert.Equal(SignatureLevel.BaselineT, plan.TargetLevel);
        Assert.Single(plan.Attachments);
    }
}
