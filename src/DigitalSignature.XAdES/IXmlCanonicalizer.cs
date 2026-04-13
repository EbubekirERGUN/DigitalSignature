using System.Xml;

namespace DigitalSignature.XAdES;

public interface IXmlCanonicalizer
{
    byte[] Canonicalize(XmlElement element);
}
