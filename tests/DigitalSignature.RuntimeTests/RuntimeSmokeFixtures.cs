using System.Text;

namespace DigitalSignature.RuntimeTests;

internal static class RuntimeSmokeFixtures
{
    public static readonly byte[] CadesPayload = Encoding.UTF8.GetBytes("Runtime CAdES payload");
    public static readonly byte[] JadesPayload = Encoding.UTF8.GetBytes("{\"invoice\":{\"id\":42,\"currency\":\"TRY\"},\"total\":123.45}");
    public static readonly byte[] XadesPayload = Encoding.UTF8.GetBytes("<Invoice Id=\"inv-42\"><Total Currency=\"TRY\">123.45</Total></Invoice>");
    public static readonly byte[] PadesPayload = Encoding.ASCII.GetBytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF");
}
