using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;

namespace DigitalSignature.PAdES;

public sealed class PAdESBaselineBVerifier
{
    private readonly CAdESBaselineBService _cadesService = new();

    public PAdESVerificationResult Verify(ReadOnlyMemory<byte> signedPdf)
    {
        var text = PdfDetachedSignatureLocator.Render(signedPdf);
        var placeholder = PdfDetachedSignatureLocator.TryLocatePlaceholder(text);

        if (placeholder is null)
        {
            return new PAdESVerificationResult(
                ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.MalformedSignature,
                    ValidationErrorCodes.MalformedSignature,
                    "PDF signature placeholder was not found.")),
                null,
                false);
        }

        var hasDetachedCades = PdfDetachedSignatureLocator.HasDetachedCadesSubFilter(text);
        if (!hasDetachedCades)
        {
            return new PAdESVerificationResult(
                ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.UnsupportedFormat,
                    ValidationErrorCodes.UnsupportedFormat,
                    "PDF signature dictionary does not declare ETSI.CAdES.detached subfilter.")),
                placeholder,
                false);
        }

        var detachedCmsSignature = PdfDetachedSignatureLocator.TryExtractCmsSignature(text, placeholder);
        if (detachedCmsSignature.IsEmpty)
        {
            return new PAdESVerificationResult(
                ValidationResult.Success(new SignatureDescriptor(
                    SignatureFormat.PAdES,
                    SignatureLevel.BaselineB,
                    null,
                    null,
                    ValidationMaterial.Empty)),
                placeholder,
                true);
        }

        try
        {
            var cadesDescriptor = _cadesService.ReadSignature(detachedCmsSignature);
            using var signingCertificate = ReadSigningCertificate(detachedCmsSignature);
            var dss = PdfDocumentSecurityStoreBuilder.Read(signedPdf, signingCertificate);
            var level = DetermineLevel(cadesDescriptor.Level, dss);
            var validationMaterial = MergeValidationMaterial(cadesDescriptor.ValidationMaterial, dss, cadesDescriptor.SigningCertificate);

            var padesDescriptor = new SignatureDescriptor(
                SignatureFormat.PAdES,
                level,
                cadesDescriptor.SigningCertificate,
                cadesDescriptor.SigningTime,
                validationMaterial,
                cadesDescriptor.SignatureAlgorithm,
                cadesDescriptor.DigestAlgorithm);

            return new PAdESVerificationResult(ValidationResult.Success(padesDescriptor), placeholder, true);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or FormatException)
        {
            return new PAdESVerificationResult(
                ValidationResult.Failure(new ValidationFailure(
                    ValidationFailureKind.MalformedSignature,
                    ValidationErrorCodes.MalformedSignature,
                    ex.Message)),
                placeholder,
                true);
        }
    }

    private static X509Certificate2? ReadSigningCertificate(ReadOnlyMemory<byte> detachedCmsSignature)
    {
        var signedCms = new System.Security.Cryptography.Pkcs.SignedCms();
        signedCms.Decode(detachedCmsSignature.ToArray());
        return signedCms.SignerInfos.Count > 0
            ? signedCms.SignerInfos[0].Certificate
            : signedCms.Certificates.Cast<X509Certificate2>().FirstOrDefault();
    }

    private static SignatureLevel DetermineLevel(SignatureLevel cadesLevel, PdfDocumentSecurityStore dss)
    {
        if (cadesLevel >= SignatureLevel.BaselineT && dss.HasEmbeddedValidationData && dss.HasVri)
        {
            return SignatureLevel.BaselineLT;
        }

        return cadesLevel;
    }

    private static ValidationMaterial MergeValidationMaterial(
        ValidationMaterial cadesValidationMaterial,
        PdfDocumentSecurityStore dss,
        SigningCertificateReference? signingCertificate)
    {
        var certificateValues = dss.CertificateValues.Count > 0
            ? dss.CertificateValues
            : cadesValidationMaterial.CertificateValues;
        var revocationValues = dss.RevocationValues.Count > 0
            ? dss.RevocationValues
            : cadesValidationMaterial.RevocationValues;
        var revocationInfo = dss.RevocationInfo.Count > 0
            ? dss.RevocationInfo
            : cadesValidationMaterial.RevocationInfo;

        return cadesValidationMaterial with
        {
            CertificateChain = BuildCertificateChainReferences(signingCertificate, cadesValidationMaterial.CertificateChain, certificateValues),
            RevocationInfo = revocationInfo,
            CertificateValues = certificateValues,
            RevocationValues = revocationValues
        };
    }

    private static IReadOnlyList<SigningCertificateReference> BuildCertificateChainReferences(
        SigningCertificateReference? signingCertificate,
        IReadOnlyList<SigningCertificateReference> existingChain,
        IReadOnlyList<ReadOnlyMemory<byte>> certificateValues)
    {
        var chain = new List<SigningCertificateReference>();
        var seenThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (signingCertificate is not null && seenThumbprints.Add(signingCertificate.Thumbprint))
        {
            chain.Add(signingCertificate);
        }

        foreach (var certificate in existingChain)
        {
            if (seenThumbprints.Add(certificate.Thumbprint))
            {
                chain.Add(certificate);
            }
        }

        foreach (var rawValue in certificateValues)
        {
            using var certificate = X509CertificateLoader.LoadCertificate(rawValue.Span);
            var reference = new SigningCertificateReference(
                certificate.Subject,
                certificate.Issuer,
                certificate.SerialNumber,
                certificate.Thumbprint,
                certificate.NotBefore.ToUniversalTime().ToString("O"),
                certificate.NotAfter.ToUniversalTime().ToString("O"));

            if (seenThumbprints.Add(reference.Thumbprint))
            {
                chain.Add(reference);
            }
        }

        return chain;
    }
}
