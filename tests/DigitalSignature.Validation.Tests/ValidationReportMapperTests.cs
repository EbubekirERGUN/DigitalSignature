using DigitalSignature.Abstractions;
using DigitalSignature.Validation.Reports;

namespace DigitalSignature.Validation.Tests;

public class ValidationReportMapperTests
{
    [Fact]
    public void Map_ShouldCreateMachineReadableReport_ForSuccessfulValidation()
    {
        var signingCertificate = new SigningCertificateReference("CN=Signer", "CN=Issuer", "01", "ABC");
        var signature = new SignatureDescriptor(
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB,
            signingCertificate,
            DateTimeOffset.Parse("2026-04-13T09:00:00Z"),
            new ValidationMaterial(
                signingCertificate,
                [signingCertificate],
                [new RevocationInfo("ocsp", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1), false, null)],
                [new TimestampMaterial("token"u8.ToArray(), DateTimeOffset.UtcNow, "1.2.3", "SHA-256")],
                []),
            SignatureAlgorithm: "1.2.840.113549.1.1.1",
            DigestAlgorithm: "2.16.840.1.101.3.4.2.1");

        var result = ValidationResult.Success(signature);
        var report = ValidationReportMapper.Map(result);

        Assert.Equal("TOTAL_PASSED", report.Conclusion.Indicator);
        Assert.True(report.Conclusion.IsSuccess);
        Assert.NotNull(report.Signature);
        Assert.Equal("CAdES", report.Signature!.Format);
        Assert.Equal(1, report.Evidence.CertificateCount);
        Assert.Equal(1, report.Evidence.RevocationObjectCount);
        Assert.Equal(1, report.Evidence.TimestampCount);
        Assert.Contains("Validation succeeded", report.Summary);
    }

    [Fact]
    public void Map_ShouldCarryFailures_ForInvalidValidation()
    {
        var result = ValidationResult.Failure(
            new ValidationFailure(
                ValidationFailureKind.TrustAnchorMissing,
                ValidationErrorCodes.TrustAnchorMissing,
                "No trust anchors were available for validation."));

        var report = ValidationReportMapper.Map(result);

        Assert.Equal("TOTAL_FAILED", report.Conclusion.Indicator);
        Assert.False(report.Conclusion.IsSuccess);
        Assert.Single(report.Failures);
        Assert.Equal(ValidationErrorCodes.TrustAnchorMissing, report.Failures[0].Code);
        Assert.Contains("Validation failed", report.Summary);
    }
}
