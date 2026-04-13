using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public interface ITimestampProvider
{
    ValueTask<TimestampResponse> GetTimestampAsync(
        TimestampRequest request,
        CancellationToken cancellationToken = default);
}
