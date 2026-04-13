using DigitalSignature.Abstractions;

namespace DigitalSignature.Validation;

internal static class CertificateValidityEvaluator
{
    public static ValidationFailure? Evaluate(SigningCertificateReference certificate, DateTimeOffset validationTime)
    {
        if (!TryParse(certificate.NotBefore, out var notBefore) || !TryParse(certificate.NotAfter, out var notAfter))
        {
            return null;
        }

        if (validationTime < notBefore || validationTime > notAfter)
        {
            return new ValidationFailure(
                ValidationFailureKind.CertificateExpired,
                ValidationErrorCodes.CertificateExpired,
                "Signing certificate is not valid at the effective validation time.");
        }

        return null;
    }

    private static bool TryParse(string? value, out DateTimeOffset parsed)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            parsed = default;
            return false;
        }

        return DateTimeOffset.TryParse(value, out parsed);
    }
}
