namespace DigitalSignature.Validation;

public sealed record SignatureValidationOptions(
    bool RequireRevocationEvidence = false,
    bool FailOnUnknownRevocationStatus = false);
