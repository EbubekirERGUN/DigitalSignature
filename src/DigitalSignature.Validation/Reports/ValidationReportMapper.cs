using DigitalSignature.Abstractions;

namespace DigitalSignature.Validation.Reports;

public static class ValidationReportMapper
{
    public static ValidationReport Map(ValidationResult result, string profile = "ETSI-TS-119-102-2-like")
    {
        ArgumentNullException.ThrowIfNull(result);

        var signature = result.Signature;
        var material = signature?.ValidationMaterial ?? ValidationMaterial.Empty;

        return new ValidationReport(
            profile,
            result.Conclusion.ToString(),
            result.EvaluatedAt,
            signature is null ? null : new ValidationReportSignature(
                signature.Format.ToString(),
                signature.Level.ToString(),
                signature.SigningCertificate?.Subject,
                signature.SigningCertificate?.Issuer,
                signature.SigningCertificate?.SerialNumber,
                signature.SigningTime?.ToString("O"),
                signature.SignatureAlgorithm,
                signature.DigestAlgorithm),
            result.Failures.Select(static failure => new ValidationReportFailure(
                failure.Code,
                failure.Kind.ToString(),
                failure.Message)).ToArray(),
            new ValidationReportEvidence(
                material.CertificateChain.Count,
                material.RevocationInfo.Count,
                material.Timestamps.Count,
                material.EvidenceRecords.Count,
                material.SigningCertificate is not null,
                material.CertificateChain.Count > 0 || material.RevocationInfo.Count > 0 || material.Timestamps.Count > 0),
            ValidationReportSummaryBuilder.Build(result));
    }
}
