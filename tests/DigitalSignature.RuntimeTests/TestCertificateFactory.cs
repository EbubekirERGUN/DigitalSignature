using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DigitalSignature.RuntimeTests;

internal static class TestCertificateFactory
{
    public static (RSA Key, X509Certificate2 Certificate) CreateSelfSignedRsa(string subjectName)
    {
        var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return (rsa, certificate);
    }
}
