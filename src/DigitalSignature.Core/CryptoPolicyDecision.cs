namespace DigitalSignature.Core;

public sealed record CryptoPolicyDecision(bool IsAllowed, SignatureSuite? SelectedSuite, string? Reason)
{
    public static CryptoPolicyDecision Allow(SignatureSuite suite) => new(true, suite, null);

    public static CryptoPolicyDecision Deny(string reason) => new(false, null, reason);
}
