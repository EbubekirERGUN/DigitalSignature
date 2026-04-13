using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed record TimestampAttachment(
    SignatureLevel TargetLevel,
    TimestampMaterial Timestamp,
    string? Description = null);
