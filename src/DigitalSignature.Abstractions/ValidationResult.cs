namespace DigitalSignature.Abstractions;

public sealed record ValidationResult(
    ValidationConclusion Conclusion,
    IReadOnlyList<ValidationFailure> Failures,
    SignatureDescriptor? Signature,
    DateTimeOffset EvaluatedAt)
{
    public static ValidationResult Success(SignatureDescriptor? signature = null) =>
        new(ValidationConclusion.Valid, Array.Empty<ValidationFailure>(), signature, DateTimeOffset.UtcNow);

    public static ValidationResult Failure(params ValidationFailure[] failures) =>
        new(ValidationConclusion.Invalid, failures, null, DateTimeOffset.UtcNow);
}
