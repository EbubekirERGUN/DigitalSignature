using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.Core.Tests;

public class Etsi119312CryptoPolicyTests
{
    private static readonly Etsi119312CryptoPolicy Policy = new();

    [Fact]
    public void SelectPreferredSuite_ShouldChooseRecommendedSigningSuite()
    {
        var suite = Policy.SelectPreferredSuite(SignatureFormat.CAdES, SignatureLevel.BaselineB);

        Assert.Equal(SignatureAlgorithmIdentifier.RsaPss, suite.SignatureAlgorithm);
        Assert.Equal(HashAlgorithmIdentifier.Sha256, suite.HashAlgorithm);
        Assert.True(suite.IsRecommended);
    }

    [Fact]
    public void SigningSuites_ShouldNotContainLegacyRsaPkcs1()
    {
        var suites = Policy.GetSupportedSuites(CryptoPolicyMode.Signing, SignatureFormat.CAdES, SignatureLevel.BaselineB);

        Assert.DoesNotContain(suites, static suite => suite.SignatureAlgorithm == SignatureAlgorithmIdentifier.RsaPkcs1);
    }

    [Fact]
    public void VerificationSuites_ShouldAllowLegacyRsaPkcs1()
    {
        var suites = Policy.GetSupportedSuites(CryptoPolicyMode.Verification, SignatureFormat.CAdES, SignatureLevel.BaselineB);

        Assert.Contains(suites, static suite => suite.SignatureAlgorithm == SignatureAlgorithmIdentifier.RsaPkcs1 && suite.IsLegacy);
    }

    [Fact]
    public void Evaluate_ShouldRejectUnsupportedSuite()
    {
        var decision = Policy.Evaluate(
            new SignatureSuite(SignatureAlgorithmIdentifier.RsaPkcs1, HashAlgorithmIdentifier.Sha512, 4096),
            CryptoPolicyMode.Signing,
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB);

        Assert.False(decision.IsAllowed);
        Assert.Null(decision.SelectedSuite);
        Assert.NotNull(decision.Reason);
    }

    [Fact]
    public void Evaluate_ShouldAllowRecommendedEcdsaSuite()
    {
        var requestedSuite = new SignatureSuite(
            SignatureAlgorithmIdentifier.Ecdsa,
            HashAlgorithmIdentifier.Sha384,
            384,
            NamedCurve.NistP384,
            IsRecommended: true);

        var decision = Policy.Evaluate(
            requestedSuite,
            CryptoPolicyMode.Signing,
            SignatureFormat.CAdES,
            SignatureLevel.BaselineB);

        Assert.True(decision.IsAllowed);
        Assert.Equal(requestedSuite, decision.SelectedSuite);
    }
}
