using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using DigitalSignature.Abstractions;
using DigitalSignature.Core;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.X509;

namespace DigitalSignature.JAdES;

public sealed class JAdESBaselineBService(IJsonCanonicalizer canonicalizer)
{
    private static readonly string[] SignatureTimeCriticalHeaders = ["sigT"];
    private static readonly JsonSerializerOptions ProtectedHeaderJsonSerializerOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public JAdESSignatureEnvelope CreateDetachedSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Level != SignatureLevel.BaselineB)
        {
            throw new ArgumentException("Compact JWS output is only supported for JAdES Baseline-B. Use CreateDetachedJsonSignature for Baseline-T/LT.", nameof(request));
        }

        return CreateSignatureEnvelope(request, signingCertificate, privateKey, suite, signingTime, "jose").Envelope;
    }

    public JAdESJsonSignatureEnvelope CreateDetachedJsonSignature(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null,
        TimestampMaterial? signatureTimestamp = null,
        IReadOnlyList<X509Certificate2>? validationCertificates = null,
        IReadOnlyList<RevocationInfo>? revocationInfo = null)
    {
        ArgumentNullException.ThrowIfNull(request);

        var baselineBEnvelope = CreateBaselineBJsonEnvelope(request, signingCertificate, privateKey, suite, signingTime);

        return request.Level switch
        {
            SignatureLevel.BaselineB => baselineBEnvelope,
            SignatureLevel.BaselineT => AttachSignatureTimestamp(baselineBEnvelope, signatureTimestamp
                ?? throw new InvalidOperationException("JAdES Baseline-T signing requires a signature timestamp token.")),
            SignatureLevel.BaselineLT => AttachValidationMaterial(
                AttachSignatureTimestamp(
                    baselineBEnvelope,
                    signatureTimestamp ?? throw new InvalidOperationException("JAdES Baseline-LT signing requires a signature timestamp token.")),
                NormalizeValidationCertificates(signingCertificate, validationCertificates),
                revocationInfo ?? throw new InvalidOperationException("JAdES Baseline-LT signing requires revocation information.")),
            _ => throw new ArgumentException($"Unsupported JAdES level '{request.Level}'.", nameof(request))
        };
    }

    public JAdESJsonSignatureEnvelope AttachSignatureTimestamp(
        JAdESJsonSignatureEnvelope baselineBEnvelope,
        TimestampMaterial signatureTimestamp)
    {
        ArgumentNullException.ThrowIfNull(baselineBEnvelope);
        ArgumentNullException.ThrowIfNull(signatureTimestamp);

        var serialization = ParseGeneralJsonSerialization(baselineBEnvelope.JsonDocument);
        var signatureEntry = GetSingleSignatureEntry(serialization);
        var components = ReadEtsiUComponents(signatureEntry.HeaderJson)
            .Where(component => !string.Equals(component.Name, "sigTst", StringComparison.Ordinal))
            .ToList();
        components.Add(new EtsiUComponentJson("sigTst", BuildSignatureTimestampComponentJson(signatureTimestamp)));

        var updatedEntry = signatureEntry with
        {
            HeaderJson = BuildUnprotectedHeaderJson(components)
        };

        return RebuildJsonEnvelope(baselineBEnvelope, updatedEntry);
    }

    public JAdESJsonSignatureEnvelope AttachValidationMaterial(
        JAdESJsonSignatureEnvelope baselineTEnvelope,
        IReadOnlyList<X509Certificate2> validationCertificates,
        IReadOnlyList<RevocationInfo> revocationInfo)
    {
        ArgumentNullException.ThrowIfNull(baselineTEnvelope);
        ArgumentNullException.ThrowIfNull(validationCertificates);
        ArgumentNullException.ThrowIfNull(revocationInfo);

        if (validationCertificates.Count == 0)
        {
            throw new InvalidOperationException("JAdES Baseline-LT embedding requires validation certificates.");
        }

        if (revocationInfo.Count == 0 || revocationInfo.All(info => info.EncodedValue.IsEmpty))
        {
            throw new InvalidOperationException("JAdES Baseline-LT embedding requires revocation values.");
        }

        var serialization = ParseGeneralJsonSerialization(baselineTEnvelope.JsonDocument);
        var signatureEntry = GetSingleSignatureEntry(serialization);
        var components = ReadEtsiUComponents(signatureEntry.HeaderJson)
            .Where(component => !string.Equals(component.Name, "xVals", StringComparison.Ordinal)
                             && !string.Equals(component.Name, "rVals", StringComparison.Ordinal)
                             && !string.Equals(component.Name, "axVals", StringComparison.Ordinal)
                             && !string.Equals(component.Name, "arVals", StringComparison.Ordinal)
                             && !string.Equals(component.Name, "tstVD", StringComparison.Ordinal)
                             && !string.Equals(component.Name, "anyValData", StringComparison.Ordinal))
            .ToList();

        if (!components.Any(component => string.Equals(component.Name, "sigTst", StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("JAdES Baseline-LT embedding requires an existing sigTst component.");
        }

        components.Add(new EtsiUComponentJson("xVals", BuildCertificateValuesComponentJson(validationCertificates)));
        components.Add(new EtsiUComponentJson("rVals", BuildRevocationValuesComponentJson(revocationInfo)));

        var updatedEntry = signatureEntry with
        {
            HeaderJson = BuildUnprotectedHeaderJson(components)
        };

        return RebuildJsonEnvelope(baselineTEnvelope, updatedEntry);
    }

    public TimestampRequest CreateArchiveTimestampRequest(
        JAdESJsonSignatureEnvelope envelope,
        HashAlgorithmIdentifier hashAlgorithm,
        string? policyOid = null,
        string? nonceHex = null,
        bool requestSignerCertificate = true)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return CreateArchiveTimestampRequest(envelope.JsonDocument, hashAlgorithm, policyOid, nonceHex, requestSignerCertificate);
    }

    public TimestampRequest CreateArchiveTimestampRequest(
        string jsonDocument,
        HashAlgorithmIdentifier hashAlgorithm,
        string? policyOid = null,
        string? nonceHex = null,
        bool requestSignerCertificate = true)
    {
        var serialization = ParseGeneralJsonSerialization(jsonDocument);
        var signatureEntry = GetSingleSignatureEntry(serialization);
        EnsureCanAttachArchiveTimestamp(jsonDocument);

        return new TimestampRequest(
            HashData(BuildArchiveTimestampImprintInput(serialization, signatureEntry), hashAlgorithm),
            GetTimestampHashAlgorithmName(hashAlgorithm),
            policyOid,
            nonceHex,
            requestSignerCertificate);
    }

    public JAdESJsonSignatureEnvelope AttachArchiveTimestamp(
        JAdESJsonSignatureEnvelope baselineLTEnvelope,
        TimestampMaterial archiveTimestamp)
    {
        ArgumentNullException.ThrowIfNull(baselineLTEnvelope);
        ArgumentNullException.ThrowIfNull(archiveTimestamp);

        if (archiveTimestamp.Token.IsEmpty)
        {
            throw new InvalidOperationException("Archive timestamp token cannot be empty.");
        }

        var serialization = ParseGeneralJsonSerialization(baselineLTEnvelope.JsonDocument);
        var signatureEntry = GetSingleSignatureEntry(serialization);
        EnsureCanAttachArchiveTimestamp(baselineLTEnvelope.JsonDocument);
        var messageImprintInput = BuildArchiveTimestampImprintInput(serialization, signatureEntry);

        if (!Rfc3161TimestampToken.TryDecode(archiveTimestamp.Token, out var timestampToken, out _))
        {
            throw new InvalidOperationException("Archive timestamp token must be a decodable RFC 3161 token.");
        }

        if (!timestampToken!.VerifySignatureForData(messageImprintInput, out _, null))
        {
            throw new InvalidOperationException("Archive timestamp token does not match the JAdES-LT covered bytes.");
        }

        var components = ReadEtsiUComponents(signatureEntry.HeaderJson).ToList();
        components.Add(new EtsiUComponentJson("arcTst", BuildArchiveTimestampComponentJson(archiveTimestamp)));

        var updatedEntry = signatureEntry with
        {
            HeaderJson = BuildUnprotectedHeaderJson(components)
        };

        return RebuildJsonEnvelope(baselineLTEnvelope, updatedEntry);
    }

    public TimestampRequest CreateSignatureTimestampRequest(
        JAdESJsonSignatureEnvelope envelope,
        HashAlgorithmIdentifier hashAlgorithm,
        string? policyOid = null,
        string? nonceHex = null,
        bool requestSignerCertificate = true)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return CreateSignatureTimestampRequest(envelope.JsonDocument, hashAlgorithm, policyOid, nonceHex, requestSignerCertificate);
    }

    public TimestampRequest CreateSignatureTimestampRequest(
        string jsonDocument,
        HashAlgorithmIdentifier hashAlgorithm,
        string? policyOid = null,
        string? nonceHex = null,
        bool requestSignerCertificate = true)
    {
        var serialization = ParseGeneralJsonSerialization(jsonDocument);
        var signatureEntry = GetSingleSignatureEntry(serialization);
        var messageImprintInput = Encoding.ASCII.GetBytes(signatureEntry.Signature);

        return new TimestampRequest(
            HashData(messageImprintInput, hashAlgorithm),
            GetTimestampHashAlgorithmName(hashAlgorithm),
            policyOid,
            nonceHex,
            requestSignerCertificate);
    }

    public SignatureDescriptor ReadSignature(string compactSerialization)
    {
        ArgumentNullException.ThrowIfNull(compactSerialization);

        var envelope = ParseEnvelope(compactSerialization);
        using var protectedHeaderDocument = JsonDocument.Parse(DecodeBase64UrlToUtf8(envelope.ProtectedHeader));
        var protectedHeader = protectedHeaderDocument.RootElement;

        return new SignatureDescriptor(
            SignatureFormat.JAdES,
            SignatureLevel.BaselineB,
            null,
            TryGetSigningTime(protectedHeader),
            ValidationMaterial.Empty,
            SignatureAlgorithm: TryGetString(protectedHeader, "alg"),
            DigestAlgorithm: GetDigestFromJwsAlgorithm(TryGetString(protectedHeader, "alg")));
    }

    public SignatureDescriptor ReadJsonSignature(string jsonDocument)
    {
        var serialization = ParseGeneralJsonSerialization(jsonDocument);
        var signatureEntry = GetSingleSignatureEntry(serialization);

        using var protectedHeaderDocument = JsonDocument.Parse(DecodeBase64UrlToUtf8(signatureEntry.Protected));
        using var signingCertificate = TryLoadSigningCertificateFromProtectedHeader(protectedHeaderDocument.RootElement);

        var timestamps = ReadSignatureTimestamps(signatureEntry.HeaderJson, signatureEntry.Signature);
        var archiveTimestamps = ReadArchiveTimestamps(signatureEntry.HeaderJson);
        var embeddedValidationData = ReadEmbeddedValidationData(signatureEntry.HeaderJson, signingCertificate);
        var certificateReference = signingCertificate is null ? null : CreateCertificateReference(signingCertificate);

        return new SignatureDescriptor(
            SignatureFormat.JAdES,
            DetermineLevel(timestamps, embeddedValidationData, archiveTimestamps),
            certificateReference,
            TryGetSigningTime(protectedHeaderDocument.RootElement),
            new ValidationMaterial(
                certificateReference,
                BuildCertificateChainReferences(signingCertificate, embeddedValidationData.CertificateValues),
                embeddedValidationData.RevocationInfo,
                timestamps,
                Array.Empty<ReadOnlyMemory<byte>>())
            {
                ArchiveTimestamps = archiveTimestamps,
                CertificateValues = embeddedValidationData.CertificateValues,
                RevocationValues = embeddedValidationData.RevocationValues
            },
            SignatureAlgorithm: TryGetString(protectedHeaderDocument.RootElement, "alg"),
            DigestAlgorithm: GetDigestFromJwsAlgorithm(TryGetString(protectedHeaderDocument.RootElement, "alg")));
    }

    public ValidationResult VerifyDetachedSignature(
        ReadOnlyMemory<byte> payload,
        string compactSerialization,
        X509Certificate2 signingCertificate)
    {
        ArgumentNullException.ThrowIfNull(compactSerialization);

        try
        {
            var envelope = ParseEnvelope(compactSerialization);
            using var protectedHeaderDocument = JsonDocument.Parse(DecodeBase64UrlToUtf8(envelope.ProtectedHeader));
            var header = protectedHeaderDocument.RootElement;
            var canonicalPayload = canonicalizer.Canonicalize(payload);
            var expectedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(canonicalPayload));

            if (!string.Equals(expectedPayload, envelope.Payload, StringComparison.Ordinal))
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.HashMismatch,
                    ValidationErrorCodes.HashMismatch,
                    "Canonicalized JSON payload does not match the JWS payload segment."));
            }

            var signatureFailure = VerifySignatureValue(signingCertificate, TryGetString(header, "alg"), envelope.ProtectedHeader, envelope.Payload, envelope.Signature);
            if (signatureFailure is not null)
            {
                return ValidationResult.Failure(signatureFailure);
            }

            return ValidationResult.Success(ReadSignature(compactSerialization));
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException or ArgumentException or NotSupportedException or InvalidOperationException)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                ex.Message));
        }
    }

    public ValidationResult VerifyDetachedJsonSignature(
        ReadOnlyMemory<byte> payload,
        string jsonDocument,
        X509Certificate2 signingCertificate)
    {
        try
        {
            var serialization = ParseGeneralJsonSerialization(jsonDocument);
            var signatureEntry = GetSingleSignatureEntry(serialization);
            using var protectedHeaderDocument = JsonDocument.Parse(DecodeBase64UrlToUtf8(signatureEntry.Protected));
            var protectedHeader = protectedHeaderDocument.RootElement;
            var canonicalPayload = canonicalizer.Canonicalize(payload);
            var expectedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(canonicalPayload));

            if (!string.Equals(expectedPayload, serialization.Payload, StringComparison.Ordinal))
            {
                return ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.HashMismatch,
                    ValidationErrorCodes.HashMismatch,
                    "Canonicalized JSON payload does not match the JAdES payload segment."));
            }

            var signatureFailure = VerifySignatureValue(signingCertificate, TryGetString(protectedHeader, "alg"), signatureEntry.Protected, serialization.Payload, signatureEntry.Signature);
            if (signatureFailure is not null)
            {
                return ValidationResult.Failure(signatureFailure);
            }

            var timestampFailure = ValidateSignatureTimestamps(signatureEntry.HeaderJson, signatureEntry.Signature);
            if (timestampFailure is not null)
            {
                return ValidationResult.Failure(timestampFailure);
            }

            var embeddedValidationFailure = ValidateEmbeddedValidationData(signatureEntry.HeaderJson, signingCertificate);
            if (embeddedValidationFailure is not null)
            {
                return ValidationResult.Failure(embeddedValidationFailure);
            }

            var archiveTimestampFailure = ValidateArchiveTimestamps(serialization, signatureEntry);
            if (archiveTimestampFailure is not null)
            {
                return ValidationResult.Failure(archiveTimestampFailure);
            }

            return ValidationResult.Success(ReadJsonSignature(jsonDocument));
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException or ArgumentException or NotSupportedException or InvalidOperationException)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                ex.Message));
        }
    }

    private JAdESJsonSignatureEnvelope CreateBaselineBJsonEnvelope(
        SignatureRequest request,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime)
    {
        var serialized = CreateSignatureEnvelope(request with { Level = SignatureLevel.BaselineB }, signingCertificate, privateKey, suite, signingTime, "jose+json");
        var signatureEntry = new JAdESJsonSignatureEntry(serialized.Envelope.ProtectedHeader, serialized.Envelope.Signature);
        var serialization = new JAdESGeneralJsonSerialization(serialized.Envelope.Payload, [signatureEntry]);
        var jsonDocument = BuildGeneralJsonSerialization(serialization);

        return new JAdESJsonSignatureEnvelope(
            serialized.Envelope.Payload,
            serialized.Envelope.ProtectedHeader,
            serialized.Envelope.Signature,
            jsonDocument,
            serialized.Envelope.CanonicalPayload,
            serialized.Envelope.SignatureMethod,
            serialized.Envelope.DigestMethod,
            serialized.ProtectedHeaderJson,
            HeaderJson: null,
            Serialization: serialization);
    }

    private static JAdESJsonSignatureEnvelope RebuildJsonEnvelope(
        JAdESJsonSignatureEnvelope previousEnvelope,
        JAdESJsonSignatureEntry updatedSignatureEntry)
    {
        var serialization = new JAdESGeneralJsonSerialization(previousEnvelope.Payload, [updatedSignatureEntry]);
        var jsonDocument = BuildGeneralJsonSerialization(serialization);

        return previousEnvelope with
        {
            Protected = updatedSignatureEntry.Protected,
            Signature = updatedSignatureEntry.Signature,
            HeaderJson = updatedSignatureEntry.HeaderJson,
            JsonDocument = jsonDocument,
            Serialization = serialization
        };
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

        if (!suite.IsRsa)
        {
            throw new NotSupportedException("Only RSA signature suites are supported for JAdES in the current implementation.");
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
                ["sigT"] = signingTime.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
                ["crit"] = SignatureTimeCriticalHeaders
            },
            ProtectedHeaderJsonSerializerOptions);

    private static string BuildGeneralJsonSerialization(JAdESGeneralJsonSerialization serialization)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });

        writer.WriteStartObject();
        writer.WriteString("payload", serialization.Payload);
        writer.WritePropertyName("signatures");
        writer.WriteStartArray();

        foreach (var signature in serialization.Signatures)
        {
            writer.WriteStartObject();
            writer.WriteString("protected", signature.Protected);

            if (!string.IsNullOrWhiteSpace(signature.HeaderJson))
            {
                writer.WritePropertyName("header");
                using var headerDocument = JsonDocument.Parse(signature.HeaderJson);
                headerDocument.RootElement.WriteTo(writer);
            }

            writer.WriteString("signature", signature.Signature);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string BuildSignatureTimestampComponentJson(TimestampMaterial signatureTimestamp)
        => JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["sigTst"] = new Dictionary<string, object?>
            {
                ["tstTokens"] = new[]
                {
                    new Dictionary<string, object?>
                    {
                        ["val"] = Convert.ToBase64String(signatureTimestamp.Token.ToArray())
                    }
                }
            }
        });

    private static string BuildArchiveTimestampComponentJson(TimestampMaterial archiveTimestamp)
        => JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["arcTst"] = new Dictionary<string, object?>
            {
                ["tstTokens"] = new[]
                {
                    new Dictionary<string, object?>
                    {
                        ["val"] = Convert.ToBase64String(archiveTimestamp.Token.ToArray())
                    }
                }
            }
        });

    private static string BuildCertificateValuesComponentJson(IReadOnlyList<X509Certificate2> validationCertificates)
        => JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["xVals"] = validationCertificates
                .GroupBy(certificate => certificate.Thumbprint, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Select(certificate => new Dictionary<string, object?>
                {
                    ["x509Cert"] = new Dictionary<string, object?>
                    {
                        ["val"] = Convert.ToBase64String(certificate.RawData)
                    }
                })
                .ToArray()
        });

    private static string BuildRevocationValuesComponentJson(IReadOnlyList<RevocationInfo> revocationInfo)
    {
        var crlValues = revocationInfo
            .Where(info => !info.EncodedValue.IsEmpty && IsCrlSource(info.Source))
            .Select(info => new Dictionary<string, object?> { ["val"] = Convert.ToBase64String(info.EncodedValue.ToArray()) })
            .ToArray();
        var ocspValues = revocationInfo
            .Where(info => !info.EncodedValue.IsEmpty && IsOcspSource(info.Source))
            .Select(info => new Dictionary<string, object?> { ["val"] = Convert.ToBase64String(info.EncodedValue.ToArray()) })
            .ToArray();

        var unsupportedRevocationSource = revocationInfo
            .FirstOrDefault(info => !info.EncodedValue.IsEmpty && !IsCrlSource(info.Source) && !IsOcspSource(info.Source));
        if (unsupportedRevocationSource is not null)
        {
            throw new InvalidOperationException($"Unsupported revocation source '{unsupportedRevocationSource.Source}' for JAdES Baseline-LT embedding.");
        }

        if (crlValues.Length == 0 && ocspValues.Length == 0)
        {
            throw new InvalidOperationException("JAdES Baseline-LT embedding requires CRL or OCSP values.");
        }

        var revocationValues = new Dictionary<string, object?>();
        if (crlValues.Length > 0)
        {
            revocationValues["crlVals"] = crlValues;
        }

        if (ocspValues.Length > 0)
        {
            revocationValues["ocspVals"] = ocspValues;
        }

        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["rVals"] = revocationValues
        });
    }

    private static string BuildUnprotectedHeaderJson(IEnumerable<EtsiUComponentJson> components)
    {
        var encodedComponents = components
            .Select(component => component.IsBase64UrlEncoded
                ? component.SerializedValue
                : Base64UrlEncode(Encoding.UTF8.GetBytes(component.Json)))
            .ToArray();

        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["etsiU"] = encodedComponents
        });
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

    private static JAdESGeneralJsonSerialization ParseGeneralJsonSerialization(string jsonDocument)
    {
        using var document = JsonDocument.Parse(jsonDocument);
        var root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("JAdES JSON serialization root must be an object.");
        }

        var payload = root.GetProperty("payload").GetString()
            ?? throw new JsonException("JAdES JSON serialization payload must be a string.");

        if (root.TryGetProperty("signatures", out var signaturesElement))
        {
            if (signaturesElement.ValueKind != JsonValueKind.Array)
            {
                throw new JsonException("JAdES signatures property must be an array.");
            }

            var signatures = new List<JAdESJsonSignatureEntry>();
            foreach (var signatureElement in signaturesElement.EnumerateArray())
            {
                signatures.Add(ParseJsonSignatureEntry(signatureElement));
            }

            if (signatures.Count == 0)
            {
                throw new JsonException("JAdES signatures array must contain at least one entry.");
            }

            return new JAdESGeneralJsonSerialization(payload, signatures);
        }

        if (root.TryGetProperty("protected", out _) && root.TryGetProperty("signature", out _))
        {
            return new JAdESGeneralJsonSerialization(payload, [ParseJsonSignatureEntry(root)]);
        }

        throw new JsonException("JAdES JSON serialization must contain either a signatures array or flattened protected/signature members.");
    }

    private static JAdESJsonSignatureEntry ParseJsonSignatureEntry(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("JAdES signature entry must be an object.");
        }

        var protectedHeader = element.GetProperty("protected").GetString()
            ?? throw new JsonException("JAdES protected header must be a string.");
        var signature = element.GetProperty("signature").GetString()
            ?? throw new JsonException("JAdES signature value must be a string.");
        var headerJson = element.TryGetProperty("header", out var headerElement)
            ? headerElement.GetRawText()
            : null;

        return new JAdESJsonSignatureEntry(protectedHeader, signature, headerJson);
    }

    private static JAdESJsonSignatureEntry GetSingleSignatureEntry(JAdESGeneralJsonSerialization serialization)
    {
        if (serialization.Signatures.Count != 1)
        {
            throw new NotSupportedException("The current JAdES implementation supports single-signature JSON serialization only.");
        }

        return serialization.Signatures[0];
    }

    private static IReadOnlyList<EtsiUComponentJson> ReadEtsiUComponents(string? headerJson)
    {
        if (string.IsNullOrWhiteSpace(headerJson))
        {
            return Array.Empty<EtsiUComponentJson>();
        }

        using var headerDocument = JsonDocument.Parse(headerJson);
        if (!headerDocument.RootElement.TryGetProperty("etsiU", out var etsiUElement))
        {
            return Array.Empty<EtsiUComponentJson>();
        }

        if (etsiUElement.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("JAdES etsiU header must be an array.");
        }

        var components = new List<EtsiUComponentJson>();
        foreach (var etsiUItem in etsiUElement.EnumerateArray())
        {
            var isBase64UrlEncoded = etsiUItem.ValueKind == JsonValueKind.String;
            var serializedValue = etsiUItem.ValueKind == JsonValueKind.String
                ? etsiUItem.GetString()!
                : etsiUItem.GetRawText();
            string rawJson = etsiUItem.ValueKind switch
            {
                JsonValueKind.String => DecodeBase64UrlToUtf8(etsiUItem.GetString()!),
                JsonValueKind.Object => etsiUItem.GetRawText(),
                _ => throw new JsonException("JAdES etsiU components must be objects or base64url-encoded JSON strings.")
            };

            using var componentDocument = JsonDocument.Parse(rawJson);
            if (componentDocument.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException("JAdES etsiU component must decode to a JSON object.");
            }

            var properties = componentDocument.RootElement.EnumerateObject().ToArray();
            if (properties.Length != 1)
            {
                throw new JsonException("Each JAdES etsiU component must contain exactly one top-level property.");
            }

            components.Add(new EtsiUComponentJson(properties[0].Name, rawJson, serializedValue, isBase64UrlEncoded));
        }

        return components;
    }

    private static IReadOnlyList<TimestampMaterial> ReadSignatureTimestamps(string? headerJson, string signatureValue)
    {
        var timestamps = new List<TimestampMaterial>();
        foreach (var component in ReadEtsiUComponents(headerJson).Where(component => string.Equals(component.Name, "sigTst", StringComparison.Ordinal)))
        {
            using var componentDocument = JsonDocument.Parse(component.Json);
            var sigTst = componentDocument.RootElement.GetProperty("sigTst");

            if (sigTst.TryGetProperty("canonAlg", out var canonAlg) && canonAlg.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined)
            {
                throw new CryptographicException("JAdES sigTst must not declare canonAlg.");
            }

            var tstTokens = sigTst.GetProperty("tstTokens");
            if (tstTokens.ValueKind != JsonValueKind.Array || tstTokens.GetArrayLength() != 1)
            {
                throw new CryptographicException("JAdES sigTst must contain exactly one timestamp token.");
            }

            var encodedToken = tstTokens[0].GetProperty("val").GetString();
            if (string.IsNullOrWhiteSpace(encodedToken))
            {
                throw new CryptographicException("JAdES sigTst token is missing its base64 value.");
            }

            byte[] tokenBytes;
            try
            {
                tokenBytes = Convert.FromBase64String(encodedToken);
            }
            catch (FormatException ex)
            {
                throw new CryptographicException("JAdES sigTst contains an invalid base64 RFC 3161 token.", ex);
            }

            if (!Rfc3161TimestampToken.TryDecode(tokenBytes, out var timestampToken, out _))
            {
                throw new CryptographicException("JAdES sigTst token could not be decoded as an RFC 3161 token.");
            }

            if (!timestampToken!.VerifySignatureForData(Encoding.ASCII.GetBytes(signatureValue), out _, null))
            {
                throw new CryptographicException("JAdES sigTst token verification failed for the base64url-encoded JWS signature value.");
            }

            timestamps.Add(new TimestampMaterial(
                tokenBytes,
                timestampToken.TokenInfo.Timestamp,
                timestampToken.TokenInfo.PolicyId?.Value,
                GetDigestFromOid(timestampToken.TokenInfo.HashAlgorithmId?.Value)));
        }

        return timestamps;
    }

    private static IReadOnlyList<TimestampMaterial> ReadArchiveTimestamps(string? headerJson)
    {
        var timestamps = new List<TimestampMaterial>();
        foreach (var component in ReadEtsiUComponents(headerJson).Where(component => string.Equals(component.Name, "arcTst", StringComparison.Ordinal)))
        {
            using var componentDocument = JsonDocument.Parse(component.Json);
            var arcTst = componentDocument.RootElement.GetProperty("arcTst");

            if (arcTst.TryGetProperty("canonAlg", out var canonAlg) && canonAlg.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined)
            {
                throw new CryptographicException("JAdES arcTst canonicalization is not supported by the current implementation.");
            }

            var tstTokens = arcTst.GetProperty("tstTokens");
            if (tstTokens.ValueKind != JsonValueKind.Array || tstTokens.GetArrayLength() != 1)
            {
                throw new CryptographicException("JAdES arcTst must contain exactly one timestamp token.");
            }

            var encodedToken = tstTokens[0].GetProperty("val").GetString();
            if (string.IsNullOrWhiteSpace(encodedToken))
            {
                throw new CryptographicException("JAdES arcTst token is missing its base64 value.");
            }

            byte[] tokenBytes;
            try
            {
                tokenBytes = Convert.FromBase64String(encodedToken);
            }
            catch (FormatException ex)
            {
                throw new CryptographicException("JAdES arcTst contains an invalid base64 RFC 3161 token.", ex);
            }

            if (!Rfc3161TimestampToken.TryDecode(tokenBytes, out var timestampToken, out _))
            {
                throw new CryptographicException("JAdES arcTst token could not be decoded as an RFC 3161 token.");
            }

            timestamps.Add(new TimestampMaterial(
                tokenBytes,
                timestampToken!.TokenInfo.Timestamp,
                timestampToken.TokenInfo.PolicyId?.Value,
                GetDigestFromOid(timestampToken.TokenInfo.HashAlgorithmId?.Value)));
        }

        return timestamps;
    }

    private static EmbeddedValidationData ReadEmbeddedValidationData(string? headerJson, X509Certificate2? signingCertificate)
    {
        var certificateValues = new List<ReadOnlyMemory<byte>>();
        var revocationValues = new List<ReadOnlyMemory<byte>>();
        var revocationInfo = new List<RevocationInfo>();

        foreach (var component in ReadEtsiUComponents(headerJson))
        {
            using var componentDocument = JsonDocument.Parse(component.Json);
            var value = componentDocument.RootElement.GetProperty(component.Name);

            if (string.Equals(component.Name, "xVals", StringComparison.Ordinal))
            {
                if (value.ValueKind != JsonValueKind.Array)
                {
                    throw new CryptographicException("JAdES xVals must be an array.");
                }

                foreach (var certificateNode in value.EnumerateArray())
                {
                    var encodedValue = certificateNode.GetProperty("x509Cert").GetProperty("val").GetString();
                    if (string.IsNullOrWhiteSpace(encodedValue))
                    {
                        throw new CryptographicException("JAdES xVals entry is missing certificate data.");
                    }

                    var rawValue = Convert.FromBase64String(encodedValue);
                    using var _ = X509CertificateLoader.LoadCertificate(rawValue);
                    certificateValues.Add(rawValue);
                }
            }
            else if (string.Equals(component.Name, "rVals", StringComparison.Ordinal))
            {
                if (value.ValueKind != JsonValueKind.Object)
                {
                    throw new CryptographicException("JAdES rVals must be an object.");
                }

                if (value.TryGetProperty("crlVals", out var crlValues))
                {
                    if (crlValues.ValueKind != JsonValueKind.Array)
                    {
                        throw new CryptographicException("JAdES rVals.crlVals must be an array.");
                    }

                    foreach (var crlNode in crlValues.EnumerateArray())
                    {
                        var encodedValue = crlNode.GetProperty("val").GetString();
                        if (string.IsNullOrWhiteSpace(encodedValue))
                        {
                            throw new CryptographicException("JAdES CRL value is missing its base64 payload.");
                        }

                        var rawValue = Convert.FromBase64String(encodedValue);
                        if (new X509CrlParser().ReadCrl(rawValue) is null)
                        {
                            throw new CryptographicException("Embedded JAdES CRL value could not be decoded.");
                        }

                        revocationValues.Add(rawValue);
                        revocationInfo.Add(MapCrlRevocationInfo(rawValue, signingCertificate));
                    }
                }

                if (value.TryGetProperty("ocspVals", out var ocspValues))
                {
                    if (ocspValues.ValueKind != JsonValueKind.Array)
                    {
                        throw new CryptographicException("JAdES rVals.ocspVals must be an array.");
                    }

                    foreach (var ocspNode in ocspValues.EnumerateArray())
                    {
                        var encodedValue = ocspNode.GetProperty("val").GetString();
                        if (string.IsNullOrWhiteSpace(encodedValue))
                        {
                            throw new CryptographicException("JAdES OCSP value is missing its base64 payload.");
                        }

                        var rawValue = Convert.FromBase64String(encodedValue);
                        _ = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(rawValue));
                        revocationValues.Add(rawValue);
                        revocationInfo.Add(MapOcspRevocationInfo(rawValue));
                    }
                }
            }
        }

        return new EmbeddedValidationData(certificateValues, revocationInfo, revocationValues);
    }

    private static ValidationFailure? ValidateSignatureTimestamps(string? headerJson, string signatureValue)
    {
        try
        {
            _ = ReadSignatureTimestamps(headerJson, signatureValue);
            return null;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException or ArgumentException)
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                $"JAdES SignatureTimeStamp could not be validated: {ex.Message}");
        }
    }

    private static ValidationFailure? ValidateEmbeddedValidationData(string? headerJson, X509Certificate2? signingCertificate)
    {
        EmbeddedValidationData validationData;
        try
        {
            validationData = ReadEmbeddedValidationData(headerJson, signingCertificate);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or ArgumentException or FormatException or JsonException)
        {
            return new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                $"Embedded JAdES-LT validation material could not be decoded: {ex.Message}");
        }

        var hasCertificateValues = validationData.CertificateValues.Count > 0;
        var hasRevocationValues = validationData.RevocationValues.Count > 0;
        if (hasCertificateValues != hasRevocationValues)
        {
            return new ValidationFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                "JAdES embedded validation material must contain both xVals and rVals.");
        }

        return null;
    }

    private static ValidationFailure? ValidateArchiveTimestamps(
        JAdESGeneralJsonSerialization serialization,
        JAdESJsonSignatureEntry signatureEntry)
    {
        try
        {
            var components = ReadEtsiUComponents(signatureEntry.HeaderJson);
            for (var index = 0; index < components.Count; index++)
            {
                var component = components[index];
                if (!string.Equals(component.Name, "arcTst", StringComparison.Ordinal))
                {
                    continue;
                }

                using var componentDocument = JsonDocument.Parse(component.Json);
                var arcTst = componentDocument.RootElement.GetProperty("arcTst");
                var encodedToken = arcTst.GetProperty("tstTokens")[0].GetProperty("val").GetString();
                var tokenBytes = Convert.FromBase64String(encodedToken!);

                if (!Rfc3161TimestampToken.TryDecode(tokenBytes, out var timestampToken, out _))
                {
                    throw new CryptographicException("JAdES arcTst token could not be decoded as an RFC 3161 token.");
                }

                var messageImprintInput = BuildArchiveTimestampImprintInput(serialization, signatureEntry, index);
                if (!timestampToken!.VerifySignatureForData(messageImprintInput, out _, null))
                {
                    throw new CryptographicException("JAdES arcTst token verification failed for the covered JAdES serialization bytes.");
                }
            }

            return null;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or JsonException or ArgumentException)
        {
            return new ValidationFailure(
                ValidationFailureKind.TimestampInvalid,
                ValidationErrorCodes.TimestampInvalid,
                $"JAdES ArchiveTimeStamp could not be validated: {ex.Message}");
        }
    }

    private static byte[] BuildArchiveTimestampImprintInput(
        JAdESGeneralJsonSerialization serialization,
        JAdESJsonSignatureEntry signatureEntry,
        int? stopBeforeComponentIndex = null)
    {
        using var stream = new MemoryStream();
        WriteAscii(stream, serialization.Payload);
        stream.WriteByte((byte)'.');
        WriteAscii(stream, signatureEntry.Protected);
        stream.WriteByte((byte)'.');
        WriteAscii(stream, signatureEntry.Signature);
        stream.WriteByte((byte)'.');

        var components = ReadEtsiUComponents(signatureEntry.HeaderJson);
        for (var index = 0; index < components.Count; index++)
        {
            if (stopBeforeComponentIndex.HasValue && index >= stopBeforeComponentIndex.Value)
            {
                break;
            }

            var component = components[index];
            if (component.IsBase64UrlEncoded)
            {
                WriteAscii(stream, component.SerializedValue);
            }
            else
            {
                WriteUtf8(stream, component.SerializedValue);
            }
        }

        return stream.ToArray();
    }

    private void EnsureCanAttachArchiveTimestamp(string jsonDocument)
    {
        var descriptor = ReadJsonSignature(jsonDocument);
        if (descriptor.Level < SignatureLevel.BaselineLT)
        {
            throw new InvalidOperationException("JAdES Baseline-LTA embedding requires an existing Baseline-LT signature.");
        }
    }

    private static void WriteAscii(Stream stream, string value)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static void WriteUtf8(Stream stream, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static ValidationFailure? VerifySignatureValue(
        X509Certificate2 signingCertificate,
        string? algorithm,
        string protectedHeader,
        string encodedPayload,
        string signature)
    {
        using var rsa = signingCertificate.GetRSAPublicKey();
        if (rsa is null)
        {
            return new ValidationFailure(
                ValidationFailureKind.UnsupportedAlgorithm,
                ValidationErrorCodes.UnsupportedAlgorithm,
                "Signing certificate does not expose an RSA public key.");
        }

        var signingInput = Encoding.ASCII.GetBytes($"{protectedHeader}.{encodedPayload}");
        var signatureBytes = Base64UrlDecode(signature);
        var verified = rsa.VerifyData(
            signingInput,
            signatureBytes,
            ToHashAlgorithmName(ParseHashAlgorithmFromJws(algorithm)),
            IsPss(algorithm) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);

        return verified
            ? null
            : new ValidationFailure(
                ValidationFailureKind.SignatureValueInvalid,
                ValidationErrorCodes.SignatureValueInvalid,
                "JWS signature verification failed.");
    }

    private static DateTimeOffset? TryGetSigningTime(JsonElement header)
        => header.TryGetProperty("sigT", out var signingTimeElement)
           && signingTimeElement.ValueKind == JsonValueKind.String
           && DateTimeOffset.TryParse(signingTimeElement.GetString(), out var parsed)
            ? parsed
            : null;

    private static string? TryGetString(JsonElement element, string propertyName)
        => element.TryGetProperty(propertyName, out var propertyValue) && propertyValue.ValueKind == JsonValueKind.String
            ? propertyValue.GetString()
            : null;

    private static X509Certificate2? TryLoadSigningCertificateFromProtectedHeader(JsonElement protectedHeader)
    {
        if (!protectedHeader.TryGetProperty("x5c", out var x5cElement) || x5cElement.ValueKind != JsonValueKind.Array || x5cElement.GetArrayLength() == 0)
        {
            return null;
        }

        var encodedCertificate = x5cElement[0].GetString();
        return string.IsNullOrWhiteSpace(encodedCertificate)
            ? null
            : X509CertificateLoader.LoadCertificate(Convert.FromBase64String(encodedCertificate));
    }

    private static SigningCertificateReference CreateCertificateReference(X509Certificate2 certificate) => new(
        certificate.Subject,
        certificate.Issuer,
        certificate.SerialNumber,
        certificate.Thumbprint,
        certificate.NotBefore.ToUniversalTime().ToString("O"),
        certificate.NotAfter.ToUniversalTime().ToString("O"));

    private static IReadOnlyList<SigningCertificateReference> BuildCertificateChainReferences(
        X509Certificate2? signingCertificate,
        IReadOnlyList<ReadOnlyMemory<byte>> certificateValues)
    {
        var chain = new List<SigningCertificateReference>();
        var seenThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (signingCertificate is not null)
        {
            AddCertificateReference(chain, seenThumbprints, signingCertificate);
        }

        foreach (var rawValue in certificateValues)
        {
            using var certificate = X509CertificateLoader.LoadCertificate(rawValue.Span);
            AddCertificateReference(chain, seenThumbprints, certificate);
        }

        return chain;
    }

    private static void AddCertificateReference(
        ICollection<SigningCertificateReference> chain,
        ISet<string> seenThumbprints,
        X509Certificate2 certificate)
    {
        if (!seenThumbprints.Add(certificate.Thumbprint))
        {
            return;
        }

        chain.Add(CreateCertificateReference(certificate));
    }

    private static IReadOnlyList<X509Certificate2> NormalizeValidationCertificates(
        X509Certificate2 signingCertificate,
        IReadOnlyList<X509Certificate2>? validationCertificates)
    {
        var certificates = new List<X509Certificate2> { signingCertificate };
        if (validationCertificates is not null)
        {
            certificates.AddRange(validationCertificates);
        }

        return certificates
            .GroupBy(certificate => certificate.Thumbprint, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToArray();
    }

    private static RevocationInfo MapCrlRevocationInfo(byte[] rawValue, X509Certificate2? signingCertificate)
    {
        var crl = new X509CrlParser().ReadCrl(rawValue) ?? throw new CryptographicException("Embedded CRL value could not be decoded.");
        bool? isRevoked = null;

        if (signingCertificate is not null)
        {
            var bcCertificate = new X509CertificateParser().ReadCertificate(signingCertificate.RawData);
            if (StringComparer.OrdinalIgnoreCase.Equals(crl.IssuerDN.ToString(), bcCertificate.IssuerDN.ToString()))
            {
                isRevoked = crl.IsRevoked(bcCertificate);
            }
        }

        return new RevocationInfo(
            "CRL",
            new DateTimeOffset(crl.ThisUpdate.ToUniversalTime()),
            crl.NextUpdate is null ? null : new DateTimeOffset(crl.NextUpdate.Value.ToUniversalTime()),
            isRevoked,
            null)
        {
            EncodedValue = rawValue
        };
    }

    private static RevocationInfo MapOcspRevocationInfo(byte[] rawValue)
    {
        var response = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(rawValue));
        return new RevocationInfo(
            "OCSP",
            new DateTimeOffset(response.TbsResponseData.ProducedAt.ToDateTime().ToUniversalTime()),
            null,
            null,
            null)
        {
            EncodedValue = rawValue
        };
    }

    private static SignatureLevel DetermineLevel(
        IReadOnlyList<TimestampMaterial> timestamps,
        EmbeddedValidationData validationData,
        IReadOnlyList<TimestampMaterial> archiveTimestamps)
    {
        if (timestamps.Count > 0 && validationData.CertificateValues.Count > 0 && validationData.RevocationValues.Count > 0 && archiveTimestamps.Count > 0)
        {
            return SignatureLevel.BaselineLTA;
        }

        if (timestamps.Count > 0 && validationData.CertificateValues.Count > 0 && validationData.RevocationValues.Count > 0)
        {
            return SignatureLevel.BaselineLT;
        }

        return timestamps.Count > 0
            ? SignatureLevel.BaselineT
            : SignatureLevel.BaselineB;
    }

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

    private static string GetTimestampHashAlgorithmName(HashAlgorithmIdentifier algorithm) => algorithm switch
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

    private static string? GetDigestFromOid(string? oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => oid
    };

    private static byte[] HashData(byte[] data, HashAlgorithmIdentifier algorithm) => algorithm switch
    {
        HashAlgorithmIdentifier.Sha256 => SHA256.HashData(data),
        HashAlgorithmIdentifier.Sha384 => SHA384.HashData(data),
        HashAlgorithmIdentifier.Sha512 => SHA512.HashData(data),
        _ => throw new NotSupportedException($"Unsupported digest algorithm: {algorithm}.")
    };

    private static bool IsCrlSource(string source) => source.Contains("CRL", StringComparison.OrdinalIgnoreCase);
    private static bool IsOcspSource(string source) => source.Contains("OCSP", StringComparison.OrdinalIgnoreCase);

    private static string Base64UrlEncode(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string text)
    {
        var normalized = text.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
        return Convert.FromBase64String(normalized);
    }

    private static string DecodeBase64UrlToUtf8(string value) => Encoding.UTF8.GetString(Base64UrlDecode(value));

    private sealed record EtsiUComponentJson(string Name, string Json, string SerializedValue, bool IsBase64UrlEncoded)
    {
        public EtsiUComponentJson(string Name, string Json)
            : this(Name, Json, JAdESBaselineBService.Base64UrlEncode(Encoding.UTF8.GetBytes(Json)), true)
        {
        }
    }

    private sealed record EmbeddedValidationData(
        IReadOnlyList<ReadOnlyMemory<byte>> CertificateValues,
        IReadOnlyList<RevocationInfo> RevocationInfo,
        IReadOnlyList<ReadOnlyMemory<byte>> RevocationValues);
}
