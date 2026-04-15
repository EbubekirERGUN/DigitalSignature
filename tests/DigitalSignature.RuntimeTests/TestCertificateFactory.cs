using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DigitalSignature.RuntimeTests;

internal static class TestCertificateFactory
{
    private static readonly DateTimeOffset RuntimeCertificateNotBefore = DateTimeOffset.Parse("2025-01-01T00:00:00Z");
    private static readonly DateTimeOffset RuntimeCertificateNotAfter = DateTimeOffset.Parse("2030-01-01T00:00:00Z");

    public static (RSA Key, X509Certificate2 Certificate) CreateSelfSignedRsa(string subjectName)
    {
        var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        var certificate = request.CreateSelfSigned(RuntimeCertificateNotBefore, RuntimeCertificateNotAfter);
        return (rsa, certificate);
    }

    public static (RSA Key, X509Certificate2 Certificate) CreateSelfSignedRsaTsa(string subjectName)
    {
        var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));

        var enhancedKeyUsages = new OidCollection { new("1.3.6.1.5.5.7.3.8") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsages, true));

        var certificate = request.CreateSelfSigned(RuntimeCertificateNotBefore, RuntimeCertificateNotAfter);
        return (rsa, certificate);
    }
}
