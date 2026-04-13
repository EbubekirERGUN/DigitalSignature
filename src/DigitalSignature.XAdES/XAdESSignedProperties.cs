namespace DigitalSignature.XAdES;

public sealed record XAdESSignedProperties(
    string SigningTime,
    string SigningCertificateDigestAlgorithm,
    string SigningCertificateDigest,
    string SigningCertificateIssuerName,
    string SigningCertificateSerialNumber,
    string DataObjectReference,
    string DataObjectMimeType,
    string DataObjectDescription);
