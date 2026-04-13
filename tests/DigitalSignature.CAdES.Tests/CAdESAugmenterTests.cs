using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;

namespace DigitalSignature.CAdES.Tests;

public class CAdESAugmenterTests
{
    [Fact]
    public async Task AugmentAsync_ShouldRequireTimestamp_ForBaselineT()
    {
        var augmenter = new CAdESAugmenter();
        var request = new AugmentationRequest(
            new SignatureDescriptor(
                SignatureFormat.CAdES,
                SignatureLevel.BaselineB,
                null,
                DateTimeOffset.UtcNow,
                ValidationMaterial.Empty),
            SignatureLevel.BaselineT,
            TemporalValidationContext.ForSigningTime(DateTimeOffset.UtcNow, null));

        var action = async () => await augmenter.AugmentAsync(request);

        await Assert.ThrowsAsync<InvalidOperationException>(action);
    }
}
