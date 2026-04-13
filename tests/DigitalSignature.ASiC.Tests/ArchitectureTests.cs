using DigitalSignature.ASiC;

namespace DigitalSignature.ASiC.Tests;

public class ArchitectureTests
{
    [Fact]
    public void ASiCAssemblyMarker_ShouldBeAccessible()
    {
        Assert.Equal("DigitalSignature.ASiC", typeof(ASiCAssemblyMarker).Namespace);
    }
}
