namespace DigitalSignature.Abstractions;

public sealed record ValidationResult(
    ValidationConclusion Conclusion,
    IReadOnlyList<ValidationFailure> Failures)
{
    public static ValidationResult Success() => new(ValidationConclusion.Valid, Array.Empty<ValidationFailure>());

    public static ValidationResult Failure(params ValidationFailure[] failures) =>
        new(ValidationConclusion.Invalid, failures);
}
