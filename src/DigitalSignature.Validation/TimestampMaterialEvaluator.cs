using DigitalSignature.Abstractions;

namespace DigitalSignature.Validation;

public static class TimestampMaterialEvaluator
{
    public static TimestampValidationResult Evaluate(
        IReadOnlyList<TimestampMaterial> timestamps,
        TimestampValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(timestamps);
        ArgumentNullException.ThrowIfNull(options);

        if (timestamps.Count == 0)
        {
            return options.RequireTimestamp
                ? TimestampValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.TimestampInvalid,
                    ValidationErrorCodes.TimestampInvalid,
                    "A timestamp was required but no timestamp material was supplied."))
                : TimestampValidationResult.Success();
        }

        if (timestamps.Any(timestamp => timestamp.Token.IsEmpty))
        {
            return TimestampValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                "Timestamp material contained an empty token payload."));
        }

        return TimestampValidationResult.Success();
    }
}
