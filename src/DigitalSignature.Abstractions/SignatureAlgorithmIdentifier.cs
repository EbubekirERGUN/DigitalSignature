namespace DigitalSignature.Abstractions;

public enum SignatureAlgorithmIdentifier
{
    Unknown = 0,
    RsaPkcs1 = 1,
    RsaPss = 2,
    Ecdsa = 3
}
