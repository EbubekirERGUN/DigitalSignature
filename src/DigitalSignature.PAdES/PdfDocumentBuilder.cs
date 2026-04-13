using System.Text;

namespace DigitalSignature.PAdES;

internal sealed class PdfDocumentBuilder
{
    private readonly List<(int Number, string Content)> _objects = [];

    public void AddObject(int number, string content) => _objects.Add((number, content));

    public byte[] Build(int rootObjectNumber)
    {
        var builder = new StringBuilder();
        builder.AppendLine("%PDF-1.7");
        builder.AppendLine("%\u00E2\u00E3\u00CF\u00D3");

        var offsets = new Dictionary<int, int>();
        foreach (var (number, content) in _objects.OrderBy(o => o.Number))
        {
            offsets[number] = Encoding.ASCII.GetByteCount(builder.ToString());
            builder.Append(number).AppendLine(" 0 obj");
            builder.Append(content);
            if (!content.EndsWith("\n", StringComparison.Ordinal))
            {
                builder.AppendLine();
            }
            builder.AppendLine("endobj");
        }

        var xrefOffset = Encoding.ASCII.GetByteCount(builder.ToString());
        var maxObjectNumber = _objects.Max(o => o.Number);
        builder.AppendLine("xref");
        builder.Append("0 ").Append(maxObjectNumber + 1).AppendLine();
        builder.AppendLine("0000000000 65535 f ");
        for (var i = 1; i <= maxObjectNumber; i++)
        {
            offsets.TryGetValue(i, out var offset);
            builder.Append(offset.ToString("D10")).AppendLine(" 00000 n ");
        }

        builder.AppendLine("trailer");
        builder.Append("<< /Size ").Append(maxObjectNumber + 1).Append(" /Root ").Append(rootObjectNumber).AppendLine(" 0 R >>");
        builder.AppendLine("startxref");
        builder.AppendLine(xrefOffset.ToString());
        builder.Append("%%EOF");

        return Encoding.ASCII.GetBytes(builder.ToString());
    }
}
