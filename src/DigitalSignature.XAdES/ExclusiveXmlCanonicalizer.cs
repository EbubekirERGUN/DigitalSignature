using System.Security.Cryptography.Xml;
using System.Xml;

namespace DigitalSignature.XAdES;

public sealed class ExclusiveXmlCanonicalizer : IXmlCanonicalizer
{
    public byte[] Canonicalize(XmlElement element)
    {
        ArgumentNullException.ThrowIfNull(element);

        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(element.OuterXml);

        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(document);

        using var stream = (Stream)transform.GetOutput(typeof(Stream));
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
}
