# DigitalSignature

.NET 10 tabanlı dijital imza kütüphanesi.

## Destek durumu

| Format | Baseline-B | Baseline-T | Baseline-LT | Durum |
|---|---:|---:|---:|---|
| CAdES | Yes | Yes | Yes | Çalışıyor |
| XAdES | Yes | Yes | Yes | Çalışıyor |
| PAdES | Yes | Yes | Yes | Çalışıyor |
| ASiC-S | Yes | Yes | Yes | Çalışıyor |
| JAdES | Yes | Partial | No | Baseline-B çalışıyor, T ve LT tamam değil |

## Kurulum

```bash
dotnet restore DigitalSignature.slnx
dotnet build DigitalSignature.slnx
dotnet test DigitalSignature.slnx
```

## Kısa kullanım örneği

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;

byte[] payload = "hello"u8.ToArray();
using RSA rsa = RSA.Create(2048);
var certificateRequest = new CertificateRequest(
    "CN=DigitalSignature Demo",
    rsa,
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);
using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddDays(-1),
    DateTimeOffset.UtcNow.AddYears(1));

var service = new CAdESBaselineBService();
var request = new SignatureRequest(
    SignatureFormat.CAdES,
    SignatureLevel.BaselineB,
    payload,
    MimeType: "text/plain");
var suite = new SignatureSuite(
    SignatureAlgorithmIdentifier.RsaPkcs1,
    HashAlgorithmIdentifier.Sha256,
    2048,
    IsRecommended: true);

var signature = service.CreateDetachedSignature(request, certificate, rsa, suite);
var validation = service.VerifyDetachedSignature(payload, signature.Data);

Console.WriteLine(validation.Conclusion);
```

## Proje yapısı

- `src/` -> kütüphane projeleri
- `tests/` -> test projeleri

## Not

Bu repo aktif geliştirme altındadır.
Özellikle JAdES-T ve JAdES-LT tarafı henüz tamamlanmış değildir.
