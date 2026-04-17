using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;

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
            var tsaPolicyOid = request.PolicyOid ?? defaultPolicyOid;
            var nonce = ParseNonce(request.Nonce);
            var bcCertificate = DotNetUtilities.FromX509Certificate(tsaCertificate);
            var bcPrivateKey = DotNetUtilities.GetRsaKeyPair(rsa).Private;

            var requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.SetCertReq(request.RequireCertificate);
            requestGenerator.SetReqPolicy(new DerObjectIdentifier(tsaPolicyOid));

            var timeStampRequest = nonce is null
                ? requestGenerator.Generate(hashAlgorithmOid.Value!, request.HashedMessage.ToArray())
                : requestGenerator.Generate(hashAlgorithmOid.Value!, request.HashedMessage.ToArray(), nonce);

            var tokenGenerator = new TimeStampTokenGenerator(
                bcPrivateKey,
                bcCertificate,
                hashAlgorithmOid.Value!,
                tsaPolicyOid);
            tokenGenerator.SetCertificates(CollectionUtilities.CreateStore([bcCertificate]));

            var encodedToken = tokenGenerator
                .Generate(timeStampRequest, CreateSerialNumber(), timestamp.UtcDateTime)
                .GetEncoded("DER");

            return ValueTask.FromResult(TimestampResponse.Success(
                new TimestampMaterial(
                    encodedToken,
                    timestamp,
                    tsaPolicyOid,
                    NormalizeHashAlgorithmName(hashAlgorithmOid))));
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidOperationException or FormatException)
        {
            return ValueTask.FromResult(TimestampResponse.Failure(
                "tsa.timestamp_generation_failed",
                ex.Message));
        }
    }

    private static BigInteger CreateSerialNumber()
    {
        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);
        serialNumber[0] &= 0x7F;
        return new BigInteger(1, serialNumber);
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

    private static BigInteger? ParseNonce(string? nonce)
    {
        if (string.IsNullOrWhiteSpace(nonce))
        {
            return null;
        }

        return new BigInteger(1, Convert.FromHexString(nonce));
    }
}
