using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.PAdES;

namespace DigitalSignature.PAdES.Tests;

public class PAdESBaselineBServiceTests
{
    [Fact]
    public void PrepareDetachedSignaturePlaceholder_ShouldAppendPdfSignatureDictionary()
    {
        var service = new PAdESBaselineBService();
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");

        var result = service.PrepareDetachedSignaturePlaceholder(pdf, 200);
        var rendered = Encoding.ASCII.GetString(result.Document.Span);

        Assert.Contains("/Type /Sig", rendered);
        Assert.Contains("/SubFilter /ETSI.CAdES.detached", rendered);
        Assert.Equal(200, result.Placeholder.ContentsLength);
        Assert.Equal(0, result.Placeholder.ByteRange.StartOffset);
        Assert.True(result.Placeholder.ByteRange.FirstLength > 0);
        Assert.True(result.Placeholder.ByteRange.SecondLength >= 0);
    }

    [Fact]
    public void ApplyDetachedSignature_ShouldEmbedHexSignature_AndReplaceByteRangeToken()
    {
        var service = new PAdESBaselineBService();
        var pdf = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
        var binding = service.PrepareDetachedSignaturePlaceholder(pdf, 20);

        var signed = service.ApplyDetachedSignature(binding, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        var rendered = Encoding.ASCII.GetString(signed.Span);

        Assert.Contains("DEADBEEF", rendered);
        Assert.DoesNotContain("**********", rendered);
    }

    [Fact]
    public void CreateSignatureDescriptor_ShouldDescribePAdESBaselineB()
    {
        var service = new PAdESBaselineBService();

        var descriptor = service.CreateSignatureDescriptor();

        Assert.Equal(SignatureFormat.PAdES, descriptor.Format);
        Assert.Equal(SignatureLevel.BaselineB, descriptor.Level);
    }
}
