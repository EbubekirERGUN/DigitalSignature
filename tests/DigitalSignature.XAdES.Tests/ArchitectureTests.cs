using DigitalSignature.XAdES;

namespace DigitalSignature.XAdES.Tests;

public class ArchitectureTests
{
    [Fact]
    public void XAdESAssemblyMarker_ShouldBeAccessible()
    {
        Assert.Equal("DigitalSignature.XAdES", typeof(XAdESAssemblyMarker).Namespace);
    }
}
