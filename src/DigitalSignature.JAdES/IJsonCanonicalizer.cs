namespace DigitalSignature.JAdES;

public interface IJsonCanonicalizer
{
    string Canonicalize(ReadOnlyMemory<byte> jsonPayload);
}
