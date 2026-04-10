using DigitalSignature.Validation;

namespace DigitalSignature.Validation.Tests;

public class ArchitectureTests
{
    [Fact]
    public void ValidationAssemblyMarker_ShouldBeAccessible()
    {
        Assert.Equal("DigitalSignature.Validation", typeof(ValidationAssemblyMarker).Namespace);
    }
}
