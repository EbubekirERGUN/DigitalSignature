namespace DigitalSignature.Abstractions;

public sealed record TemporalValidationContext(
    DateTimeOffset ValidationTime,
    DateTimeOffset? SigningTime,
    bool PreferSigningTime,
    IReadOnlyList<TimestampMaterial> Timestamps)
{
    public DateTimeOffset EffectiveValidationTime => PreferSigningTime && SigningTime.HasValue
        ? SigningTime.Value
        : ValidationTime;

    public static TemporalValidationContext ForSigningTime(
        DateTimeOffset validationTime,
        DateTimeOffset? signingTime,
        IReadOnlyList<TimestampMaterial>? timestamps = null)
    {
        return new(validationTime, signingTime, PreferSigningTime: signingTime.HasValue, timestamps ?? Array.Empty<TimestampMaterial>());
    }
}
