using System.Xml;
using DigitalSignature.Abstractions;
using DigitalSignature.Validation;

namespace DigitalSignature.XAdES;

public sealed class XAdESBaselineBValidator(
    XAdESBaselineBService xadesService,
    SignatureValidationEngine validationEngine)
{
    public async ValueTask<XAdESVerificationResult> ValidateAsync(
        ReadOnlyMemory<byte> xmlSignature,
        TemporalValidationContext temporalContext,
        SignatureValidationOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var integrityResult = xadesService.VerifyEnvelopedSignature(xmlSignature);
        var metadata = ReadVerificationMetadata(xmlSignature);

        if (integrityResult.Conclusion != ValidationConclusion.Valid || integrityResult.Signature is null)
        {
            return new XAdESVerificationResult(
                integrityResult,
                metadata.HasSignedPropertiesReference,
                metadata.HasCanonicalizationMethod,
                metadata.CanonicalizationMethod);
        }

        var input = SignatureValidationInput.Create(
            xmlSignature,
            integrityResult.Signature,
            integrityResult,
            temporalContext);

        var validation = await validationEngine.ValidateAsync(input, options, cancellationToken);
        return new XAdESVerificationResult(
            validation,
            metadata.HasSignedPropertiesReference,
            metadata.HasCanonicalizationMethod,
            metadata.CanonicalizationMethod);
    }

    private static (bool HasSignedPropertiesReference, bool HasCanonicalizationMethod, string? CanonicalizationMethod) ReadVerificationMetadata(ReadOnlyMemory<byte> xmlBytes)
    {
        try
        {
            var xml = new XmlDocument();
            xml.LoadXml(System.Text.Encoding.UTF8.GetString(xmlBytes.Span));

            var ns = new XmlNamespaceManager(xml.NameTable);
            ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            var canonicalizationMethod = xml.SelectSingleNode("/*/*[local-name()='Signature']/*[local-name()='SignedInfo']/*[local-name()='CanonicalizationMethod']", ns) as XmlElement;
            var references = xml.SelectNodes("/*/*[local-name()='Signature']/*[local-name()='SignedInfo']/*[local-name()='Reference']", ns);
            var hasSignedPropertiesReference = references?.Cast<XmlElement>().Any(reference =>
                string.Equals(reference.GetAttribute("Type"), "http://uri.etsi.org/01903#SignedProperties", StringComparison.Ordinal)) == true;

            return (
                hasSignedPropertiesReference,
                canonicalizationMethod is not null,
                canonicalizationMethod?.GetAttribute("Algorithm"));
        }
        catch
        {
            return (false, false, null);
        }
    }
}
