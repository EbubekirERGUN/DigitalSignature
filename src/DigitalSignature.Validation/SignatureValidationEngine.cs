using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.Validation;

public sealed class SignatureValidationEngine(
    ICertificateChainValidator certificateChainValidator,
    ITrustAnchorProvider trustAnchorProvider)
{
    public async ValueTask<ValidationResult> ValidateAsync(
        SignatureValidationInput input,
        SignatureValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);

        options ??= new SignatureValidationOptions();

        if (input.IntegrityResult.Conclusion != ValidationConclusion.Valid || input.Signature.SigningCertificate is null)
        {
            return input.IntegrityResult;
        }

        var certificateValidityFailure = CertificateValidityEvaluator.Evaluate(
            input.Signature.SigningCertificate,
            input.TemporalContext.EffectiveValidationTime);

        if (certificateValidityFailure is not null)
        {
            return ValidationResult.Failure(certificateValidityFailure);
        }

        var revocationFailure = EvaluateRevocation(input, options);
        if (revocationFailure is not null)
        {
            return ValidationResult.Failure(revocationFailure);
        }

        var trustAnchors = await trustAnchorProvider.GetTrustAnchorsAsync(
            input.Signature.Format,
            input.TemporalContext,
            cancellationToken);

        if (trustAnchors.Count == 0)
        {
            return ValidationResult.Failure(new ValidationFailure(
                ValidationFailureKind.TrustAnchorMissing,
                ValidationErrorCodes.TrustAnchorMissing,
                "No trust anchors were available for validation."));
        }

        var chainRequest = CertificateChainValidationRequest.Create(
            input.Signature.SigningCertificate,
            input.TemporalContext.EffectiveValidationTime,
            input.TemporalContext.PreferSigningTime,
            intermediateCertificates: input.Signature.ValidationMaterial.CertificateChain,
            trustAnchors: trustAnchors);

        var chainResult = await certificateChainValidator.ValidateAsync(chainRequest, cancellationToken);
        if (!chainResult.IsTrusted)
        {
            return ValidationResult.Failure(chainResult.Failures.ToArray());
        }

        return ValidationResult.Success(input.Signature);
    }

    private static ValidationFailure? EvaluateRevocation(SignatureValidationInput input, SignatureValidationOptions options)
    {
        var revocationInfo = input.Signature.ValidationMaterial.RevocationInfo;
        if (revocationInfo.Count == 0)
        {
            return options.RequireRevocationEvidence
                ? new ValidationFailure(
                    ValidationFailureKind.RevocationStatusUnknown,
                    ValidationErrorCodes.RevocationStatusUnknown,
                    "No revocation evidence was available for the signing certificate.")
                : null;
        }

        if (revocationInfo.Any(info => info.IsRevoked == true))
        {
            return new ValidationFailure(
                ValidationFailureKind.CertificateRevoked,
                ValidationErrorCodes.CertificateRevoked,
                "Signing certificate is marked as revoked by supplied revocation evidence.");
        }

        if (options.FailOnUnknownRevocationStatus && revocationInfo.Any(info => info.IsRevoked is null))
        {
            return new ValidationFailure(
                ValidationFailureKind.RevocationStatusUnknown,
                ValidationErrorCodes.RevocationStatusUnknown,
                "Revocation evidence did not produce a deterministic certificate status.");
        }

        return null;
    }
}
