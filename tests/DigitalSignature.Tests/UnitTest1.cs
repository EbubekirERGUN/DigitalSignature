namespace DigitalSignature.Tests;

public class UnitTest1
{
    [Fact]
    public void ProjectName_ShouldBe_DigitalSignature()
    {
        Assert.Equal("DigitalSignature", SignaturePlaceholder.ProjectName);
    }
}
