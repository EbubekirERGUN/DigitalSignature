using DigitalSignature.CAdES;

namespace DigitalSignature.CAdES.Tests;

public class ArchitectureTests
{
    [Fact]
    public void CAdESAssemblyMarker_ShouldBeAccessible()
    {
        Assert.Equal("DigitalSignature.CAdES", typeof(CAdESAssemblyMarker).Namespace);
    }
}
