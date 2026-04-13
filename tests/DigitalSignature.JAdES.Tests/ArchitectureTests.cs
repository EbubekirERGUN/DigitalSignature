using DigitalSignature.JAdES;

namespace DigitalSignature.JAdES.Tests;

public class ArchitectureTests
{
    [Fact]
    public void JAdESAssemblyMarker_ShouldBeAccessible()
    {
        Assert.Equal("DigitalSignature.JAdES", typeof(JAdESAssemblyMarker).Namespace);
    }
}
