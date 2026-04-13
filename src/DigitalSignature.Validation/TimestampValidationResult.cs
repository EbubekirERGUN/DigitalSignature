using DigitalSignature.Abstractions;

namespace DigitalSignature.Validation;

public sealed record TimestampValidationResult(
    bool IsValid,
    IReadOnlyList<ValidationFailure> Failures)
{
    public static TimestampValidationResult Success() => new(true, Array.Empty<ValidationFailure>());

    public static TimestampValidationResult Failure(params ValidationFailure[] failures) => new(false, failures);
}
