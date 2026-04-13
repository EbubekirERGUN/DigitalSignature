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
        var metadata = ReadMetadata(compactSerialization);

        if (integrityResult.Conclusion != ValidationConclusion.Valid || integrityResult.Signature is null)
        {
            return new JAdESVerificationResult(
                integrityResult,
                metadata.HasTypHeader,
                metadata.HasCanonicalizationClaim,
                metadata.Algorithm);
        }

        var enrichedSignature = integrityResult.Signature with
        {
            SigningCertificate = new SigningCertificateReference(
                signingCertificate.Subject,
                signingCertificate.Issuer,
                signingCertificate.SerialNumber,
                signingCertificate.Thumbprint,
                signingCertificate.NotBefore.ToUniversalTime().ToString("O"),
                signingCertificate.NotAfter.ToUniversalTime().ToString("O")),
            ValidationMaterial = new ValidationMaterial(
                new SigningCertificateReference(
                    signingCertificate.Subject,
                    signingCertificate.Issuer,
                    signingCertificate.SerialNumber,
                    signingCertificate.Thumbprint,
                    signingCertificate.NotBefore.ToUniversalTime().ToString("O"),
                    signingCertificate.NotAfter.ToUniversalTime().ToString("O")),
                [new SigningCertificateReference(
                    signingCertificate.Subject,
                    signingCertificate.Issuer,
                    signingCertificate.SerialNumber,
                    signingCertificate.Thumbprint,
                    signingCertificate.NotBefore.ToUniversalTime().ToString("O"),
                    signingCertificate.NotAfter.ToUniversalTime().ToString("O"))],
                Array.Empty<RevocationInfo>(),
                Array.Empty<TimestampMaterial>(),
                Array.Empty<ReadOnlyMemory<byte>>())
        };

        var input = SignatureValidationInput.Create(payload, enrichedSignature, ValidationResult.Success(enrichedSignature), temporalContext);
        var validation = await validationEngine.ValidateAsync(input, options, cancellationToken);

        return new JAdESVerificationResult(
            validation,
            metadata.HasTypHeader,
            metadata.HasCanonicalizationClaim,
            metadata.Algorithm);
    }

    private static (bool HasTypHeader, bool HasCanonicalizationClaim, string? Algorithm) ReadMetadata(string compactSerialization)
    {
        try
        {
            var headerSegment = compactSerialization.Split('.')[0];
            var normalized = headerSegment.Replace('-', '+').Replace('_', '/');
            normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
            var headerJson = Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
            var header = JsonSerializer.Deserialize<Dictionary<string, object?>>(headerJson) ?? new();

            return (
                header.ContainsKey("typ"),
                header.TryGetValue("jades_c14n", out var c14n) && string.Equals(c14n?.ToString(), "RFC8785", StringComparison.Ordinal),
                header.TryGetValue("alg", out var alg) ? alg?.ToString() : null);
        }
        catch
        {
            return (false, false, null);
        }
    }
}
