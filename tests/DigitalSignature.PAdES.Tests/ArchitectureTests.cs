using DigitalSignature.PAdES;

namespace DigitalSignature.PAdES.Tests;

public class ArchitectureTests
{
    [Fact]
    public void PAdESAssemblyMarker_ShouldBeAccessible()
    {
        Assert.Equal("DigitalSignature.PAdES", typeof(PAdESAssemblyMarker).Namespace);
    }
}
