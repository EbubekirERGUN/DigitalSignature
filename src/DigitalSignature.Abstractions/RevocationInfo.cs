namespace DigitalSignature.Abstractions;

public sealed record RevocationInfo(
    string Source,
    DateTimeOffset? ThisUpdate,
    DateTimeOffset? NextUpdate,
    bool? IsRevoked,
    DateTimeOffset? RevokedAt,
    string? Reason = null);
