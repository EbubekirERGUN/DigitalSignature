namespace DigitalSignature.PAdES;

public static class PdfSignatureDictionaryBuilder
{
    public static string BuildPlaceholderDictionary(int estimatedContentsHexLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(estimatedContentsHexLength);

        var placeholder = new string('0', estimatedContentsHexLength);
        return $"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 ********** ********** **********] /Contents <{placeholder}> >>";
    }
}
