namespace DigitalSignature.Abstractions;

public sealed record ValidationFailure(
    ValidationFailureKind Kind,
    string Code,
    string Message);
