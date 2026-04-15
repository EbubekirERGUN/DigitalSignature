using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DigitalSignature.Abstractions;
using DigitalSignature.Validation;

namespace DigitalSignature.JAdES;

public sealed class JAdESBaselineBValidator(
    JAdESBaselineBService jadesService,
    SignatureValidationEngine validationEngine)
{
    public async ValueTask<JAdESVerificationResult> ValidateDetachedAsync(
        ReadOnlyMemory<byte> payload,
        string compactSerialization,
        TemporalValidationContext temporalContext,
        X509Certificate2 signingCertificate,
        SignatureValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var integrityResult = jadesService.VerifyDetachedSignature(payload, compactSerialization, signingCertificate);
        var metadata = ReadCompactMetadata(compactSerialization);

        if (integrityResult.Conclusion != ValidationConclusion.Valid || integrityResult.Signature is null)
        {
            return new JAdESVerificationResult(
                integrityResult,
                metadata.HasTypHeader,
                metadata.HasCanonicalizationClaim,
                metadata.Algorithm);
        }

        var enrichedSignature = EnrichSignatureWithSigningCertificate(integrityResult.Signature, signingCertificate);
        var input = SignatureValidationInput.Create(payload, enrichedSignature, ValidationResult.Success(enrichedSignature), temporalContext);
        var validation = await validationEngine.ValidateAsync(input, options, cancellationToken);

        return new JAdESVerificationResult(
            validation,
            metadata.HasTypHeader,
            metadata.HasCanonicalizationClaim,
            metadata.Algorithm);
    }

    public async ValueTask<JAdESVerificationResult> ValidateDetachedJsonAsync(
        ReadOnlyMemory<byte> payload,
        string jsonSerialization,
        TemporalValidationContext temporalContext,
        X509Certificate2 signingCertificate,
        SignatureValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var integrityResult = jadesService.VerifyDetachedJsonSignature(payload, jsonSerialization, signingCertificate);
        var metadata = ReadJsonMetadata(jsonSerialization);

        if (integrityResult.Conclusion != ValidationConclusion.Valid || integrityResult.Signature is null)
        {
            return new JAdESVerificationResult(
                integrityResult,
                metadata.HasTypHeader,
                metadata.HasCanonicalizationClaim,
                metadata.Algorithm);
        }

        var enrichedSignature = EnrichSignatureWithSigningCertificate(integrityResult.Signature, signingCertificate);
        var input = SignatureValidationInput.Create(payload, enrichedSignature, ValidationResult.Success(enrichedSignature), temporalContext);
        var validation = await validationEngine.ValidateAsync(input, options, cancellationToken);

        return new JAdESVerificationResult(
            validation,
            metadata.HasTypHeader,
            metadata.HasCanonicalizationClaim,
            metadata.Algorithm);
    }

    private static SignatureDescriptor EnrichSignatureWithSigningCertificate(
        SignatureDescriptor signature,
        X509Certificate2 signingCertificate)
    {
        var certificateReference = CreateCertificateReference(signingCertificate);
        var existingMaterial = signature.ValidationMaterial;
        var certificateChain = existingMaterial.CertificateChain.Count == 0
            ? new[] { certificateReference }
            : MergeCertificateChain(existingMaterial.CertificateChain, certificateReference);

        return signature with
        {
            SigningCertificate = certificateReference,
            ValidationMaterial = existingMaterial with
            {
                SigningCertificate = certificateReference,
                CertificateChain = certificateChain
            }
        };
    }

    private static IReadOnlyList<SigningCertificateReference> MergeCertificateChain(
        IReadOnlyList<SigningCertificateReference> existingChain,
        SigningCertificateReference signingCertificate)
    {
        var chain = new List<SigningCertificateReference> { signingCertificate };
        chain.AddRange(existingChain.Where(reference => !string.Equals(reference.Thumbprint, signingCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase)));
        return chain;
    }

    private static (bool HasTypHeader, bool HasCanonicalizationClaim, string? Algorithm) ReadCompactMetadata(string compactSerialization)
    {
        try
        {
            var headerSegment = compactSerialization.Split('.')[0];
            using var headerDocument = JsonDocument.Parse(DecodeBase64UrlToUtf8(headerSegment));
            return ReadMetadata(headerDocument.RootElement);
        }
        catch
        {
            return (false, false, null);
        }
    }

    private static (bool HasTypHeader, bool HasCanonicalizationClaim, string? Algorithm) ReadJsonMetadata(string jsonSerialization)
    {
        try
        {
            using var document = JsonDocument.Parse(jsonSerialization);
            var root = document.RootElement;
            string protectedHeader = root.TryGetProperty("signatures", out var signatures)
                ? signatures[0].GetProperty("protected").GetString()!
                : root.GetProperty("protected").GetString()!;

            using var headerDocument = JsonDocument.Parse(DecodeBase64UrlToUtf8(protectedHeader));
            return ReadMetadata(headerDocument.RootElement);
        }
        catch
        {
            return (false, false, null);
        }
    }

    private static (bool HasTypHeader, bool HasCanonicalizationClaim, string? Algorithm) ReadMetadata(JsonElement header)
        => (
            header.TryGetProperty("typ", out _),
            header.TryGetProperty("jades_c14n", out var c14n) && c14n.ValueKind == JsonValueKind.String && string.Equals(c14n.GetString(), "RFC8785", StringComparison.Ordinal),
            header.TryGetProperty("alg", out var alg) && alg.ValueKind == JsonValueKind.String ? alg.GetString() : null);

    private static SigningCertificateReference CreateCertificateReference(X509Certificate2 certificate) => new(
        certificate.Subject,
        certificate.Issuer,
        certificate.SerialNumber,
        certificate.Thumbprint,
        certificate.NotBefore.ToUniversalTime().ToString("O"),
        certificate.NotAfter.ToUniversalTime().ToString("O"));

    private static string DecodeBase64UrlToUtf8(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
    }
}
