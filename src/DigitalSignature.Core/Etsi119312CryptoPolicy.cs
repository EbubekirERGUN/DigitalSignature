using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed class Etsi119312CryptoPolicy : ICryptoPolicy
{
    private static readonly SignatureSuite[] SigningSuites =
    [
        new(SignatureAlgorithmIdentifier.RsaPss, HashAlgorithmIdentifier.Sha256, 2048, IsRecommended: true),
        new(SignatureAlgorithmIdentifier.RsaPss, HashAlgorithmIdentifier.Sha384, 3072, IsRecommended: true),
        new(SignatureAlgorithmIdentifier.Ecdsa, HashAlgorithmIdentifier.Sha256, 256, NamedCurve.NistP256, IsRecommended: true),
        new(SignatureAlgorithmIdentifier.Ecdsa, HashAlgorithmIdentifier.Sha384, 384, NamedCurve.NistP384, IsRecommended: true)
    ];

    private static readonly SignatureSuite[] VerificationOnlySuites =
    [
        new(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha256, 2048, IsLegacy: true),
        new(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha384, 3072, IsLegacy: true)
    ];

    public IReadOnlyList<SignatureSuite> GetSupportedSuites(CryptoPolicyMode mode, SignatureFormat format, SignatureLevel level)
    {
        return mode == CryptoPolicyMode.Signing
            ? SigningSuites
            : MergeVerificationSuites();
    }

    public CryptoPolicyDecision Evaluate(
        SignatureSuite requestedSuite,
        CryptoPolicyMode mode,
        SignatureFormat format,
        SignatureLevel level)
    {
        foreach (var suite in GetSupportedSuites(mode, format, level))
        {
            if (suite == requestedSuite)
            {
                return CryptoPolicyDecision.Allow(suite);
            }
        }

        return CryptoPolicyDecision.Deny($"Signature suite '{requestedSuite}' is not allowed for {mode}.");
    }

    public SignatureSuite SelectPreferredSuite(SignatureFormat format, SignatureLevel level)
    {
        return SigningSuites[0];
    }

    private static IReadOnlyList<SignatureSuite> MergeVerificationSuites()
    {
        var suites = new SignatureSuite[SigningSuites.Length + VerificationOnlySuites.Length];
        SigningSuites.CopyTo(suites, 0);
        VerificationOnlySuites.CopyTo(suites, SigningSuites.Length);
        return suites;
    }
}
