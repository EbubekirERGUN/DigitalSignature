using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public interface ICryptoPolicy
{
    IReadOnlyList<SignatureSuite> GetSupportedSuites(CryptoPolicyMode mode, SignatureFormat format, SignatureLevel level);

    CryptoPolicyDecision Evaluate(
        SignatureSuite requestedSuite,
        CryptoPolicyMode mode,
        SignatureFormat format,
        SignatureLevel level);

    SignatureSuite SelectPreferredSuite(SignatureFormat format, SignatureLevel level);
}
