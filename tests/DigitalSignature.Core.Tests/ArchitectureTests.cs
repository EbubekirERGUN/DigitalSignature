using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.Core.Tests;

public class ArchitectureTests
{
    [Fact]
    public void CoreAssemblyMarker_ShouldBeAccessible()
    {
        Assert.Equal("DigitalSignature.Core", typeof(CoreAssemblyMarker).Namespace);
    }

    [Fact]
    public void SharedEnums_ShouldExposeKnownValues()
    {
        Assert.Contains(SignatureFormat.CAdES, Enum.GetValues<SignatureFormat>());
        Assert.Contains(SignatureLevel.BaselineB, Enum.GetValues<SignatureLevel>());
    }
}
