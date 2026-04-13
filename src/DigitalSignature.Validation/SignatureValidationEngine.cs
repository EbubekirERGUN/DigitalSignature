using DigitalSignature.Abstractions;
using DigitalSignature.Core;

namespace DigitalSignature.Validation;

public sealed class SignatureValidationEngine(
    ICertificateChainValidator certificateChainValidator,
    ITrustAnchorProvider trustAnchorProvider,
    RevocationEvidenceCollector? revocationEvidenceCollector = null)
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

        var revocationInfo = input.Signature.ValidationMaterial.RevocationInfo;
        if (revocationInfo.Count == 0 && revocationEvidenceCollector is not null)
        {
            var collectedEvidence = await revocationEvidenceCollector.CollectAsync(
                input.Signature.SigningCertificate,
                input.Signature.ValidationMaterial.CertificateChain.Skip(1).FirstOrDefault(),
                input.TemporalContext,
                cancellationToken);

            revocationInfo = collectedEvidence
                .Select(MapRevocationInfo)
                .ToArray();
        }

        var revocationFailure = EvaluateRevocation(revocationInfo, options);
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

        var enrichedSignature = input.Signature with
        {
            ValidationMaterial = input.Signature.ValidationMaterial with
            {
                RevocationInfo = revocationInfo,
                CertificateChain = chainResult.Chain.Count > 0
                    ? chainResult.Chain
                    : input.Signature.ValidationMaterial.CertificateChain
            }
        };

        _ = SignatureValidationContext.Create(input, trustAnchors, revocationInfo, chainResult);
        return ValidationResult.Success(enrichedSignature);
    }

    private static ValidationFailure? EvaluateRevocation(IReadOnlyList<RevocationInfo> revocationInfo, SignatureValidationOptions options)
    {
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

    private static RevocationInfo MapRevocationInfo(CertificateRevocationEvidence evidence)
    {
        return new RevocationInfo(
            evidence.Source.ToString(),
            evidence.ThisUpdate,
            evidence.NextUpdate,
            evidence.Status switch
            {
                CertificateRevocationStatus.Good => false,
                CertificateRevocationStatus.Revoked => true,
                _ => null
            },
            evidence.RevokedAt,
            evidence.Reason);
    }
}
