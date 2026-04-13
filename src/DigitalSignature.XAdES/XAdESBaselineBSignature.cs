namespace DigitalSignature.XAdES;

public sealed record XAdESBaselineBSignature(
    string XmlDocument,
    string SignatureId,
    string SignedPropertiesId,
    string DataObjectReferenceId,
    XAdESSignedProperties SignedProperties);
