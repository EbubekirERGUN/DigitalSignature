using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.JAdES;

public sealed class JAdESBaselineBService(IJsonCanonicalizer canonicalizer)
{
    public JAdESSignatureEnvelope CreateDetachedSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null)
        => CreateSignatureEnvelope(request, signingCertificate, privateKey, suite, signingTime, "jose").Envelope;

    public JAdESJsonSignatureEnvelope CreateDetachedJsonSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null)
    {
        var serialized = CreateSignatureEnvelope(request, signingCertificate, privateKey, suite, signingTime, "jose+json");
        var jsonDocument = BuildGeneralJsonSerialization(
            serialized.Envelope.Payload,
            serialized.Envelope.ProtectedHeader,
            serialized.Envelope.Signature);

        return new JAdESJsonSignatureEnvelope(
            serialized.Envelope.Payload,
            serialized.Envelope.ProtectedHeader,
            serialized.Envelope.Signature,
            jsonDocument,
            serialized.Envelope.CanonicalPayload,
            serialized.Envelope.SignatureMethod,
            serialized.Envelope.DigestMethod,
            serialized.ProtectedHeaderJson);
    }

    public SignatureDescriptor ReadSignature(string compactSerialization)
    {
        var envelope = ParseEnvelope(compactSerialization);
        var header = ParseProtectedHeader(envelope.ProtectedHeader);

        return new SignatureDescriptor(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            null,
            TryGetSigningTime(header),
            ValidationMaterial.Empty,
            SignatureAlgorithm: header.TryGetValue("alg", out var algorithm) ? algorithm?.ToString() : null,
            DigestAlgorithm: GetDigestFromJwsAlgorithm(header.TryGetValue("alg", out algorithm) ? algorithm?.ToString() : null));
    }

    public ValidationResult VerifyDetachedSignature(
        ReadOnlyMemory<byte> payload,
        string compactSerialization,
        X509Certificate2 signingCertificate)
    {
        try
        {
            var envelope = ParseEnvelope(compactSerialization);
            var header = ParseProtectedHeader(envelope.ProtectedHeader);
            var canonicalPayload = canonicalizer.Canonicalize(payload);
            var expectedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(canonicalPayload));

            if (!string.Equals(expectedPayload, envelope.Payload, StringComparison.Ordinal))
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.HashMismatch,
                    ValidationErrorCodes.HashMismatch,
                    "Canonicalized JSON payload does not match the JWS payload segment."));
            }

            using var rsa = signingCertificate.GetRSAPublicKey();
            if (rsa is null)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.UnsupportedAlgorithm,
                    ValidationErrorCodes.UnsupportedAlgorithm,
                    "Signing certificate does not expose an RSA public key."));
            }

            var alg = header.TryGetValue("alg", out var algorithm) ? algorithm?.ToString() : null;
            var signingInput = Encoding.ASCII.GetBytes($"{envelope.ProtectedHeader}.{envelope.Payload}");
            var signatureBytes = Base64UrlDecode(envelope.Signature);
            var verified = rsa.VerifyData(
                signingInput,
                signatureBytes,
                ToHashAlgorithmName(ParseHashAlgorithmFromJws(alg)),
                IsPss(alg) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);

            if (!verified)
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.SignatureValueInvalid,
                    ValidationErrorCodes.SignatureValueInvalid,
                    "JWS signature verification failed."));
            }

            return ValidationResult.Success(ReadSignature(compactSerialization));
        }
        catch (JsonException ex)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                ex.Message));
        }
        catch (FormatException ex)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                ex.Message));
        }
    }

    private (JAdESSignatureEnvelope Envelope, string ProtectedHeaderJson) CreateSignatureEnvelope(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime,
        string type)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(suite);

        if (request.Format != SignatureFormat.JAdES)
        {
            throw new ArgumentException("JAdES service only accepts JAdES requests.", nameof(request));
        }

        if (request.Level != SignatureLevel.BaselineB)
        {
            throw new ArgumentException("JAdES Baseline-B signing requires SignatureLevel.BaselineB.", nameof(request));
        }

        if (!suite.IsRsa)
        {
            throw new NotSupportedException("Only RSA signature suites are supported for JAdES Baseline-B in the current implementation.");
        }

        var canonicalPayload = canonicalizer.Canonicalize(request.Payload);
        var protectedHeaderJson = BuildProtectedHeaderJson(signingCertificate, suite, signingTime ?? DateTimeOffset.UtcNow, type);
        var protectedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(protectedHeaderJson));
        var encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(canonicalPayload));
        var signingInput = Encoding.ASCII.GetBytes($"{protectedHeader}.{encodedPayload}");
        var signatureBytes = privateKey.SignData(
            signingInput,
            ToHashAlgorithmName(suite.HashAlgorithm),
            suite.SignatureAlgorithm == SignatureAlgorithmIdentifier.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
        var signature = Base64UrlEncode(signatureBytes);

        return (
            new JAdESSignatureEnvelope(
                protectedHeader,
                encodedPayload,
                signature,
                $"{protectedHeader}.{encodedPayload}.{signature}",
                canonicalPayload,
                GetJwsAlgorithm(suite),
                GetDigestLabel(suite.HashAlgorithm)),
            protectedHeaderJson);
    }

    private static string BuildProtectedHeaderJson(
        X509Certificate2 signingCertificate,
        SignatureSuite suite,
        DateTimeOffset signingTime,
        string type)
        => JsonSerializer.Serialize(
            new Dictionary<string, object?>
            {
                ["alg"] = GetJwsAlgorithm(suite),
                ["cty"] = "json",
                ["kid"] = BuildKeyIdentifier(signingCertificate),
                ["x5t#S256"] = Base64UrlEncode(SHA256.HashData(signingCertificate.RawData)),
                ["x5c"] = new[] { Convert.ToBase64String(signingCertificate.RawData) },
                ["typ"] = type,
                ["sigT"] = signingTime.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                ["crit"] = new[] { "sigT" }
            },
            new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });

    private static string BuildGeneralJsonSerialization(string payload, string protectedHeader, string signature)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });

        writer.WriteStartObject();
        writer.WriteString("payload", payload);
        writer.WritePropertyName("signatures");
        writer.WriteStartArray();
        writer.WriteStartObject();
        writer.WriteString("protected", protectedHeader);
        writer.WriteString("signature", signature);
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string BuildKeyIdentifier(X509Certificate2 signingCertificate)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        var directoryNameTag = new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true);

        writer.PushSequence();
        writer.PushSequence();
        writer.PushSequence(directoryNameTag);
        writer.WriteEncodedValue(signingCertificate.IssuerName.RawData);
        writer.PopSequence(directoryNameTag);
        writer.PopSequence();
        writer.WriteInteger(ParseCertificateSerialNumber(signingCertificate.SerialNumber));
        writer.PopSequence();

        return Convert.ToBase64String(writer.Encode());
    }

    private static BigInteger ParseCertificateSerialNumber(string serialNumber)
        => string.IsNullOrWhiteSpace(serialNumber)
            ? BigInteger.Zero
            : BigInteger.Parse($"00{serialNumber}", NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static (string ProtectedHeader, string Payload, string Signature) ParseEnvelope(string compactSerialization)
    {
        var parts = compactSerialization.Split('.');
        if (parts.Length != 3 || parts.Any(string.IsNullOrWhiteSpace))
        {
            throw new FormatException("JWS compact serialization must contain three dot-separated segments.");
        }

        return (parts[0], parts[1], parts[2]);
    }

    private static Dictionary<string, object?> ParseProtectedHeader(string encodedProtectedHeader)
    {
        var json = Encoding.UTF8.GetString(Base64UrlDecode(encodedProtectedHeader));
        return JsonSerializer.Deserialize<Dictionary<string, object?>>(json)
            ?? throw new JsonException("Protected JWS header could not be parsed.");
    }

    private static DateTimeOffset? TryGetSigningTime(IReadOnlyDictionary<string, object?> header)
        => header.TryGetValue("sigT", out var signingTime) && DateTimeOffset.TryParse(signingTime?.ToString(), out var parsed)
            ? parsed
            : null;

    private static string GetJwsAlgorithm(SignatureSuite suite) => suite.SignatureAlgorithm switch
    {
        SignatureAlgorithmIdentifier.RsaPkcs1 when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha256 => "RS256",
        SignatureAlgorithmIdentifier.RsaPkcs1 when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha384 => "RS384",
        SignatureAlgorithmIdentifier.RsaPkcs1 when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha512 => "RS512",
        SignatureAlgorithmIdentifier.RsaPss when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha256 => "PS256",
        SignatureAlgorithmIdentifier.RsaPss when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha384 => "PS384",
        SignatureAlgorithmIdentifier.RsaPss when suite.HashAlgorithm == HashAlgorithmIdentifier.Sha512 => "PS512",
        _ => throw new NotSupportedException("Unsupported JWS algorithm suite.")
    };

    private static string? GetDigestFromJwsAlgorithm(string? alg) => alg switch
    {
        "RS256" or "PS256" => "SHA-256",
        "RS384" or "PS384" => "SHA-384",
        "RS512" or "PS512" => "SHA-512",
        _ => null
    };

    private static string GetDigestLabel(HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => "SHA-256",
        HashAlgorithmIdentifier.Sha384 => "SHA-384",
        HashAlgorithmIdentifier.Sha512 => "SHA-512",
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static bool IsPss(string? alg) => alg is "PS256" or "PS384" or "PS512";

    private static HashAlgorithmIdentifier ParseHashAlgorithmFromJws(string? alg) => alg switch
    {
        "RS256" or "PS256" => HashAlgorithmIdentifier.Sha256,
        "RS384" or "PS384" => HashAlgorithmIdentifier.Sha384,
        "RS512" or "PS512" => HashAlgorithmIdentifier.Sha512,
        _ => throw new NotSupportedException($"Unsupported JWS algorithm: {alg}.")
    };

    private static HashAlgorithmName ToHashAlgorithmName(HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => HashAlgorithmName.SHA256,
        HashAlgorithmIdentifier.Sha384 => HashAlgorithmName.SHA384,
        HashAlgorithmIdentifier.Sha512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static string Base64UrlEncode(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string text)
    {
        var normalized = text.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
        return Convert.FromBase64String(normalized);
    }
}
