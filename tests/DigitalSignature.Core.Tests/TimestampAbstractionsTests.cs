using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.Core.Tests;

public class TimestampAbstractionsTests
{
    [Fact]
    public void TimestampResponse_Success_ShouldCarryTimestamp()
    {
        var timestamp = new TimestampMaterial("token"u8.ToArray(), DateTimeOffset.UtcNow, "1.2.3", "SHA-256");

        var response = TimestampResponse.Success(timestamp);

        Assert.True(response.IsSuccess);
        Assert.NotNull(response.Timestamp);
        Assert.Equal("1.2.3", response.Timestamp!.PolicyOid);
    }

    [Fact]
    public void TimestampResponse_Failure_ShouldCarryError()
    {
        var response = TimestampResponse.Failure("tsa.unavailable", "TSA endpoint did not respond.");

        Assert.False(response.IsSuccess);
        Assert.Null(response.Timestamp);
        Assert.Equal("tsa.unavailable", response.FailureCode);
    }

    [Fact]
    public void TimestampAttachmentPlan_Empty_ShouldCreateNoAttachments()
    {
        var plan = TimestampAttachmentPlan.Empty(SignatureFormat.CAdES, SignatureLevel.BaselineB, SignatureLevel.BaselineT);

        Assert.Empty(plan.Attachments);
        Assert.Equal(SignatureLevel.BaselineT, plan.TargetLevel);
    }
}
