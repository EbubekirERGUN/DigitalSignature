namespace DigitalSignature.XAdES;

public sealed record XAdESBaselineBSignature(
    string XmlDocument,
    string SignedPropertiesId,
    XAdESSignedProperties SignedProperties);
