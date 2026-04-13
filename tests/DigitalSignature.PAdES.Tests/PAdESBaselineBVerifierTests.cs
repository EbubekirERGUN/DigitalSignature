using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.PAdES;

namespace DigitalSignature.PAdES.Tests;

public class PAdESBaselineBVerifierTests
{
    [Fact]
    public void Verify_ShouldReturnSuccess_WhenPAdESDetachedSubFilterExists()
    {
        var service = new PAdESBaselineBService();
        var verifier = new PAdESBaselineBVerifier();
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
        var binding = service.PrepareDetachedSignaturePlaceholder(pdf, 20);
        var signed = service.ApplyDetachedSignature(binding, new byte[] { 0xAA, 0xBB });

        var result = verifier.Verify(signed);

        Assert.Equal(ValidationConclusion.Valid, result.Validation.Conclusion);
        Assert.True(result.HasDetachedCAdESSignature);
        Assert.NotNull(result.Placeholder);
        Assert.Equal(SignatureFormat.PAdES, result.Validation.Signature!.Format);
    }

    [Fact]
    public void Verify_ShouldFail_WhenPdfDoesNotContainSignaturePlaceholder()
    {
        var verifier = new PAdESBaselineBVerifier();
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\nplain-content\n%%EOF");

        var result = verifier.Verify(pdf);

        Assert.Equal(ValidationConclusion.Invalid, result.Validation.Conclusion);
        Assert.Contains(result.Validation.Failures, failure => failure.Code == ValidationErrorCodes.MalformedSignature);
    }
}
