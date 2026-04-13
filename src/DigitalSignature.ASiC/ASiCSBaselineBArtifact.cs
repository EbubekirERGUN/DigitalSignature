using DigitalSignature.Abstractions;

namespace DigitalSignature.ASiC;

public sealed record ASiCSBaselineBArtifact(
    SignatureArtifact Container,
    string PayloadEntryName,
    string SignatureEntryName);
