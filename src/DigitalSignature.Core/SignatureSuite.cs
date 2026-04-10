using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed record SignatureSuite(
    SignatureAlgorithmIdentifier SignatureAlgorithm,
    HashAlgorithmIdentifier HashAlgorithm,
    int KeySizeBits,
    NamedCurve Curve = NamedCurve.None,
    bool IsRecommended = false,
    bool IsLegacy = false)
{
    public bool IsRsa => SignatureAlgorithm is SignatureAlgorithmIdentifier.RsaPkcs1 or SignatureAlgorithmIdentifier.RsaPss;

    public bool IsEllipticCurve => SignatureAlgorithm == SignatureAlgorithmIdentifier.Ecdsa;

    public override string ToString() => Curve == NamedCurve.None
        ? $"{SignatureAlgorithm}/{HashAlgorithm}/{KeySizeBits}"
        : $"{SignatureAlgorithm}/{HashAlgorithm}/{Curve}";
}
