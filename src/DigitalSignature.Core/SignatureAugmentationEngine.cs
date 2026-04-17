using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed class SignatureAugmentationEngine(IEnumerable<ISignatureAugmenter> augmenters)
{
    private readonly Dictionary<SignatureFormat, ISignatureAugmenter> _augmenters = augmenters.ToDictionary(augmenter => augmenter.Profile.Format);

    public ValueTask<AugmentationResult> AugmentAsync(
        AugmentationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_augmenters.TryGetValue(request.Signature.Format, out var augmenter))
        {
            throw new NotSupportedException($"No augmentation workflow is registered for signature format '{request.Signature.Format}'.");
        }

        EnsureSupportedTarget(request.TargetLevel, augmenter.Profile);
        return augmenter.AugmentAsync(request, cancellationToken);
    }

    private static void EnsureSupportedTarget(SignatureLevel targetLevel, SignatureAugmentationProfile profile)
    {
        var supported = targetLevel switch
        {
            SignatureLevel.BaselineT => profile.SupportsBaselineT,
            SignatureLevel.BaselineLT => profile.SupportsBaselineLT,
            SignatureLevel.BaselineLTA => profile.SupportsBaselineLTA,
            _ => false
        };

        if (!supported)
        {
            throw new NotSupportedException($"Augmentation target '{targetLevel}' is not supported for format '{profile.Format}'.");
        }
    }
}
