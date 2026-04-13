using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public interface ISignatureAugmenter
{
    SignatureAugmentationProfile Profile { get; }

    ValueTask<AugmentationResult> AugmentAsync(
        AugmentationRequest request,
        CancellationToken cancellationToken = default);
}
