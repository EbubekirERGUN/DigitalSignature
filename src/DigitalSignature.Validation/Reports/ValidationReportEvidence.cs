namespace DigitalSignature.Validation.Reports;

public sealed record ValidationReportEvidence(
    int CertificateCount,
    int RevocationObjectCount,
    int TimestampCount,
    int EvidenceRecordCount,
    bool HasSigningCertificate,
    bool HasTrustMaterial);
