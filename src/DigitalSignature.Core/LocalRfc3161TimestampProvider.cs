using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;

namespace DigitalSignature.Core;

public sealed class LocalRfc3161TimestampProvider(
    X509Certificate2 tsaCertificate,
    string defaultPolicyOid = "1.2.3.4.1",
    DateTimeOffset? fixedTimestamp = null) : ITimestampProvider
{
    public ValueTask<TimestampResponse> GetTimestampAsync(
        TimestampRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var rsa = tsaCertificate.GetRSAPrivateKey();
            if (rsa is null)
            {
                return ValueTask.FromResult(TimestampResponse.Failure(
                    "tsa.private_key_missing",
                    "The TSA certificate does not expose an RSA private key."));
            }

            var timestamp = fixedTimestamp ?? DateTimeOffset.UtcNow;
            var hashAlgorithmOid = ResolveHashAlgorithmOid(request.HashAlgorithm);
            var tokenInfo = new Rfc3161TimestampTokenInfo(
                new Oid(request.PolicyOid ?? defaultPolicyOid),
                hashAlgorithmOid,
                request.HashedMessage,
                CreateSerialNumber(),
                timestamp,
                null,
                false,
                ParseNonce(request.Nonce),
                null,
                new X509ExtensionCollection());

            var signedCms = new SignedCms(
                new ContentInfo(new Oid("1.2.840.113549.1.9.16.1.4"), tokenInfo.Encode()),
                detached: false);

            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, tsaCertificate)
            {
                IncludeOption = request.RequireCertificate ? X509IncludeOption.EndCertOnly : X509IncludeOption.None,
                DigestAlgorithm = hashAlgorithmOid
            };

            signer.SignedAttributes.Add(CreateSigningCertificateV2Attribute(tsaCertificate, hashAlgorithmOid));
            signedCms.ComputeSignature(signer, silent: true);

            return ValueTask.FromResult(TimestampResponse.Success(
                new TimestampMaterial(
                    signedCms.Encode(),
                    timestamp,
                    request.PolicyOid ?? defaultPolicyOid,
                    NormalizeHashAlgorithmName(hashAlgorithmOid))));
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidOperationException or FormatException)
        {
            return ValueTask.FromResult(TimestampResponse.Failure(
                "tsa.timestamp_generation_failed",
                ex.Message));
        }
    }

    private static Pkcs9AttributeObject CreateSigningCertificateV2Attribute(X509Certificate2 certificate, Oid hashAlgorithmOid)
    {
        var certificateHash = HashCertificate(certificate.RawData, hashAlgorithmOid);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier(hashAlgorithmOid.Value!);
        writer.PopSequence();
        writer.WriteOctetString(certificateHash);
        writer.PopSequence();
        writer.PopSequence();
        writer.PopSequence();

        return new Pkcs9AttributeObject("1.2.840.113549.1.9.16.2.47", writer.Encode());
    }

    private static byte[] CreateSerialNumber()
    {
        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        serialNumber[0] &= 0x7F;

        return serialNumber[0] == 0
            ? [0x01, .. serialNumber[1..]]
            : serialNumber;
    }

    private static Oid ResolveHashAlgorithmOid(string? hashAlgorithm)
    {
        var normalized = hashAlgorithm?.Trim().ToUpperInvariant();
        return normalized switch
        {
            "SHA-256" or "SHA256" or "2.16.840.1.101.3.4.2.1" => new Oid("2.16.840.1.101.3.4.2.1"),
            "SHA-384" or "SHA384" or "2.16.840.1.101.3.4.2.2" => new Oid("2.16.840.1.101.3.4.2.2"),
            "SHA-512" or "SHA512" or "2.16.840.1.101.3.4.2.3" => new Oid("2.16.840.1.101.3.4.2.3"),
            _ => throw new NotSupportedException($"Unsupported timestamp hash algorithm: {hashAlgorithm}.")
        };
    }

    private static string NormalizeHashAlgorithmName(Oid hashAlgorithmOid) => hashAlgorithmOid.Value switch
    {
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => hashAlgorithmOid.Value ?? string.Empty
    };

    private static ReadOnlyMemory<byte>? ParseNonce(string? nonce)
    {
        if (string.IsNullOrWhiteSpace(nonce))
        {
            return null;
        }

        return Convert.FromHexString(nonce);
    }

    private static byte[] HashCertificate(ReadOnlySpan<byte> rawData, Oid hashAlgorithmOid) => hashAlgorithmOid.Value switch
    {
        "2.16.840.1.101.3.4.2.1" => SHA256.HashData(rawData),
        "2.16.840.1.101.3.4.2.2" => SHA384.HashData(rawData),
        "2.16.840.1.101.3.4.2.3" => SHA512.HashData(rawData),
        _ => throw new NotSupportedException($"Unsupported timestamp hash algorithm OID: {hashAlgorithmOid.Value}.")
    };
}
