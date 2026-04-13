using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed record SignatureAugmentationProfile(
    SignatureFormat Format,
    bool SupportsBaselineT,
    bool SupportsBaselineLT,
    bool SupportsBaselineLTA);
