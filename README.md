# DigitalSignature

.NET 10 tabanlı, ETSI odaklı dijital imza geliştirme ve doğrulama projesi.

## Kapsam

Bu repo şu formatlar üzerinde çalışır:

- CAdES
- XAdES
- PAdES
- JAdES
- ASiC-S

Ayrıca şu alanları da kapsar:

- validation engine
- timestamp integration
- augmentation flow
- ETSI checker interoperability
- runtime smoke verification

## Mevcut durum

| Format | Baseline-B | Baseline-T | Local | ETSI |
|---|---:|---:|---:|---:|
| CAdES | Done | Done | Pass | Pass |
| XAdES | Done | Done | Pass | Pass |
| PAdES | Done | Done | Pass | Pass |
| ASiC-S | Done | Done | Pass | Pass |
| JAdES | Done | In progress / parked | Mixed | In progress |

Not:
- JAdES Baseline-B checker uyumlu
- JAdES-T tarafında ETSI ile local model arasında serialization / verification uyumu üzerinde ek çalışma gerekiyor

## Hızlı başlangıç

```bash
dotnet restore DigitalSignature.slnx
dotnet build DigitalSignature.slnx
dotnet test DigitalSignature.slnx
```

## Repo yapısı

- `src/DigitalSignature.Abstractions` → ortak model ve kontratlar
- `src/DigitalSignature.Core` → ortak çekirdek servisler
- `src/DigitalSignature.CAdES` → CAdES üretim/doğrulama
- `src/DigitalSignature.XAdES` → XAdES üretim/doğrulama
- `src/DigitalSignature.PAdES` → PAdES üretim/doğrulama
- `src/DigitalSignature.JAdES` → JAdES üretim/doğrulama
- `src/DigitalSignature.ASiC` → ASiC-S container üretim/doğrulama
- `src/DigitalSignature.Validation` → format bağımsız validation engine
- `tests/DigitalSignature.*.Tests` → format ve bileşen testleri

## Doğrulama yaklaşımı

Projede her önemli değişiklik için şu sıra izlenir:

1. unit test
2. runtime smoke test
3. artifact generation
4. ETSI checker validation

Runtime artifact çıktıları yerelde şu klasörde üretilir:

- `artifacts/runtime-demo`

## Takip dosyaları

- `ROADMAP.md` -> uzun vadeli teknik yön
- `STATUS.md` -> güncel durum
- `WORKFLOW.md` -> çalışma modeli ve doğrulama akışı

