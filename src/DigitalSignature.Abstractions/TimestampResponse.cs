namespace DigitalSignature.Abstractions;

public sealed record TimestampResponse(
    bool IsSuccess,
    TimestampMaterial? Timestamp,
    string? FailureCode = null,
    string? FailureMessage = null)
{
    public static TimestampResponse Success(TimestampMaterial timestamp) => new(true, timestamp);

    public static TimestampResponse Failure(string failureCode, string? failureMessage = null) =>
        new(false, null, failureCode, failureMessage);
}
