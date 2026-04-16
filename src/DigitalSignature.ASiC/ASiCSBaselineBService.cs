using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSignature.Abstractions;
using DigitalSignature.CAdES;
using DigitalSignature.Core;

namespace DigitalSignature.ASiC;

public sealed class ASiCSBaselineBService
{
    public const string ContainerMediaType = "application/vnd.etsi.asic-s+zip";
    public const string MimeTypeEntryName = "mimetype";
    public const string SignatureEntryName = "META-INF/signature.p7s";

    private readonly CAdESBaselineBService _cadesService = new();

    public TimestampRequest CreateArchiveTimestampRequest(
        ReadOnlyMemory<byte> containerBytes,
        HashAlgorithmIdentifier hashAlgorithm)
    {
        var inspection = GetValidInspection(containerBytes);
        var signatureData = PrepareSignatureForArchiveTimestamp(inspection.SignatureData!, inspection.PayloadData!);
        return _cadesService.CreateArchiveTimestampRequest(signatureData, hashAlgorithm);
    }

    public ASiCSBaselineBArtifact AttachArchiveTimestamp(
        ASiCSBaselineBArtifact artifact,
        TimestampMaterial archiveTimestamp)
    {
        ArgumentNullException.ThrowIfNull(artifact);

        var inspection = GetValidInspection(artifact.Container.Data);
        var preparedSignature = PrepareSignatureForArchiveTimestamp(inspection.SignatureData!, inspection.PayloadData!);
        var signatureDescriptor = _cadesService.ReadSignature(preparedSignature);
        if (signatureDescriptor.Level < SignatureLevel.BaselineLT)
        {
            throw new InvalidOperationException("ASiC-S Baseline-LTA requires a container with an embedded CAdES Baseline-LT signature.");
        }

        var updatedSignature = _cadesService.AttachArchiveTimestamp(
            new SignatureArtifact(SignatureFormat.CAdES, signatureDescriptor.Level, preparedSignature, "application/pkcs7-signature"),
            archiveTimestamp);

        var containerBytes = StoredZipContainerBuilder.Build(
            [
                new StoredZipEntry(MimeTypeEntryName, Encoding.UTF8.GetBytes(ContainerMediaType)),
                new StoredZipEntry(inspection.PayloadEntryName!, inspection.PayloadData!),
                new StoredZipEntry(inspection.SignatureEntryName ?? SignatureEntryName, updatedSignature.Data.ToArray())
            ],
            archiveTimestamp.CreatedAt);

        return new ASiCSBaselineBArtifact(
            new SignatureArtifact(SignatureFormat.ASiC, SignatureLevel.BaselineLTA, containerBytes, ContainerMediaType),
            inspection.PayloadEntryName!,
            inspection.SignatureEntryName ?? SignatureEntryName);
    }

    public ASiCSBaselineBArtifact CreateContainer(
        SignatureRequest request,
        string payloadEntryName,
        X509Certificate2 signingCertificate,
        RSA privateKey,
        SignatureSuite suite,
        DateTimeOffset? signingTime = null,
        TimestampMaterial? signatureTimestamp = null,
        IReadOnlyList<X509Certificate2>? validationCertificates = null,
        IReadOnlyList<RevocationInfo>? revocationInfo = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(suite);

        if (request.Format != SignatureFormat.ASiC)
        {
            throw new ArgumentException("ASiC service only accepts ASiC requests.", nameof(request));
        }

        if (request.Level is not SignatureLevel.BaselineB and not SignatureLevel.BaselineT and not SignatureLevel.BaselineLT)
        {
            throw new ArgumentException("ASiC signing currently supports only SignatureLevel.BaselineB, SignatureLevel.BaselineT and SignatureLevel.BaselineLT.", nameof(request));
        }

        if (!suite.IsRsa)
        {
            throw new NotSupportedException("Only RSA signature suites are supported for ASiC Baseline signatures in the current implementation.");
        }

        if (request.Level is SignatureLevel.BaselineT or SignatureLevel.BaselineLT && signatureTimestamp is null)
        {
            throw new InvalidOperationException($"ASiC {request.Level} signing requires a CAdES signature timestamp token.");
        }

        if (request.Level == SignatureLevel.BaselineLT && (revocationInfo is null || revocationInfo.Count == 0 || revocationInfo.All(info => info.EncodedValue.IsEmpty)))
        {
            throw new InvalidOperationException("ASiC Baseline-LT signing requires embedded revocation values for the CAdES signature.");
        }

        var normalizedPayloadEntryName = NormalizePayloadEntryName(payloadEntryName);
        var cadesRequest = new SignatureRequest(
            SignatureFormat.CAdES,
            request.Level,
            request.Payload,
            request.MimeType,
            "detached");

        var signature = _cadesService.CreateDetachedSignature(
            cadesRequest,
            signingCertificate,
            privateKey,
            suite,
            signingTime,
            signatureTimestamp,
            validationCertificates,
            revocationInfo);
        var createdAt = signingTime ?? signatureTimestamp?.CreatedAt ?? DateTimeOffset.UtcNow;
        var containerBytes = StoredZipContainerBuilder.Build(
            [
                new StoredZipEntry(MimeTypeEntryName, Encoding.UTF8.GetBytes(ContainerMediaType)),
                new StoredZipEntry(normalizedPayloadEntryName, request.Payload.ToArray()),
                new StoredZipEntry(SignatureEntryName, signature.Data.ToArray())
            ],
            createdAt);

        return new ASiCSBaselineBArtifact(
            new SignatureArtifact(SignatureFormat.ASiC, request.Level, containerBytes, ContainerMediaType),
            normalizedPayloadEntryName,
            SignatureEntryName);
    }

    public ASiCSBaselineBVerificationResult VerifyContainer(ReadOnlyMemory<byte> containerBytes)
    {
        try
        {
            var inspection = InspectContainer(containerBytes);
            var structuralFailure = GetStructuralFailure(inspection);
            if (structuralFailure is not null)
            {
                return inspection.ToResult(ValidationResult.Failure(structuralFailure));
            }

            ValidationResult signatureValidation;
            if (_cadesService.IsDetachedSignature(inspection.SignatureData!))
            {
                signatureValidation = _cadesService.VerifyDetachedSignature(inspection.PayloadData!, inspection.SignatureData!);
            }
            else
            {
                signatureValidation = VerifyContainerWithEncapsulatedSignature(inspection);
            }

            if (signatureValidation.Conclusion == ValidationConclusion.Valid && signatureValidation.Signature is not null)
            {
                signatureValidation = ValidationResult.Success(ToAsicDescriptor(signatureValidation.Signature));
            }

            return inspection.ToResult(signatureValidation);
        }
        catch (InvalidDataException ex)
        {
            return Failure(ex.Message, ValidationFailureKind.MalformedSignature, ValidationErrorCodes.MalformedSignature);
        }
        catch (CryptographicException ex)
        {
            return Failure(ex.Message, ValidationFailureKind.MalformedSignature, ValidationErrorCodes.MalformedSignature);
        }
    }

    private byte[] PrepareSignatureForArchiveTimestamp(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> payload)
        => _cadesService.IsDetachedSignature(signature)
            ? _cadesService.EncapsulateDetachedContent(signature, payload)
            : signature.ToArray();

    private ValidationResult VerifyContainerWithEncapsulatedSignature(ContainerInspection inspection)
    {
        var signatureValidation = _cadesService.VerifyAttachedSignature(inspection.SignatureData!);
        if (signatureValidation.Conclusion != ValidationConclusion.Valid)
        {
            return signatureValidation;
        }

        var encapsulatedContent = _cadesService.ReadEncapsulatedContent(inspection.SignatureData!);
        if (encapsulatedContent is null)
        {
            return ValidationResult.Failure(CreateFailure(
                ValidationFailureKind.MalformedSignature,
                ValidationErrorCodes.MalformedSignature,
                "The embedded CAdES signature does not contain encapsulated content."));
        }

        if (!encapsulatedContent.AsSpan().SequenceEqual(inspection.PayloadData!))
        {
            return ValidationResult.Failure(CreateFailure(
                ValidationFailureKind.HashMismatch,
                ValidationErrorCodes.HashMismatch,
                "The encapsulated CAdES content does not match the ASiC-S payload file."));
        }

        return signatureValidation;
    }

    private static string NormalizePayloadEntryName(string payloadEntryName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payloadEntryName);

        var normalized = payloadEntryName.Replace('\\', '/');
        if (normalized.StartsWith("/", StringComparison.Ordinal) ||
            normalized.Contains("../", StringComparison.Ordinal) ||
            normalized.Contains("/..", StringComparison.Ordinal) ||
            normalized.Contains("//", StringComparison.Ordinal) ||
            normalized.Equals(MimeTypeEntryName, StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith("/", StringComparison.Ordinal) ||
            normalized.Contains("/", StringComparison.Ordinal))
        {
            throw new ArgumentException("ASiC-S payload entry must be a single root-level filename outside META-INF.", nameof(payloadEntryName));
        }

        return normalized;
    }

    private static ContainerInspection InspectContainer(ReadOnlyMemory<byte> containerBytes)
    {
        var isMimeTypeFileFirst = TryReadFirstLocalFileHeader(containerBytes.Span, out var firstEntryName, out var compressionMethod) &&
            string.Equals(firstEntryName, MimeTypeEntryName, StringComparison.Ordinal);
        var isMimeTypeFileStored = compressionMethod == 0;

        using var stream = new MemoryStream(containerBytes.ToArray(), writable: false);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);

        var mimeTypeEntry = archive.GetEntry(MimeTypeEntryName);
        var signatureEntry = archive.GetEntry(SignatureEntryName);
        var payloadEntries = archive.Entries
            .Where(entry =>
                !string.Equals(entry.FullName, MimeTypeEntryName, StringComparison.Ordinal) &&
                !entry.FullName.StartsWith("META-INF/", StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(entry.Name))
            .ToArray();

        return new ContainerInspection(
            mimeTypeEntry is not null,
            mimeTypeEntry is null ? null : ReadUtf8(mimeTypeEntry),
            isMimeTypeFileFirst,
            isMimeTypeFileStored,
            signatureEntry is not null,
            payloadEntries.Length == 1,
            payloadEntries.SingleOrDefault()?.FullName,
            signatureEntry?.FullName,
            payloadEntries.Length == 1 ? ReadAllBytes(payloadEntries[0]) : null,
            signatureEntry is null ? null : ReadAllBytes(signatureEntry));
    }

    private static ValidationFailure? GetStructuralFailure(ContainerInspection inspection)
    {
        if (!inspection.HasMimeTypeFile)
        {
            return CreateFailure(ValidationFailureKind.UnsupportedFormat, ValidationErrorCodes.UnsupportedFormat, "ASiC-S container is missing the mimetype entry.");
        }

        if (!string.Equals(inspection.MimeTypeContent, ContainerMediaType, StringComparison.Ordinal))
        {
            return CreateFailure(ValidationFailureKind.UnsupportedFormat, ValidationErrorCodes.UnsupportedFormat, "ASiC-S mimetype entry does not match the expected ETSI media type.");
        }

        if (!inspection.IsMimeTypeFileFirst)
        {
            return CreateFailure(ValidationFailureKind.UnsupportedFormat, ValidationErrorCodes.UnsupportedFormat, "ASiC-S mimetype entry is not the first ZIP entry.");
        }

        if (!inspection.IsMimeTypeFileStored)
        {
            return CreateFailure(ValidationFailureKind.UnsupportedFormat, ValidationErrorCodes.UnsupportedFormat, "ASiC-S mimetype entry must be stored without compression.");
        }

        if (!inspection.HasSignatureFile)
        {
            return CreateFailure(ValidationFailureKind.MalformedSignature, ValidationErrorCodes.MalformedSignature, "ASiC-S container is missing META-INF/signature.p7s.");
        }

        if (!inspection.HasSinglePayloadFile)
        {
            return CreateFailure(ValidationFailureKind.UnsupportedFormat, ValidationErrorCodes.UnsupportedFormat, "ASiC-S container must contain exactly one signed payload file.");
        }

        return null;
    }

    private static ContainerInspection GetValidInspection(ReadOnlyMemory<byte> containerBytes)
    {
        var inspection = InspectContainer(containerBytes);
        var structuralFailure = GetStructuralFailure(inspection);
        if (structuralFailure is not null)
        {
            throw new InvalidOperationException(structuralFailure.Message);
        }

        return inspection;
    }

    private static ASiCSBaselineBVerificationResult Failure(string message, ValidationFailureKind kind, string code) =>
        new(
            ValidationResult.Failure(CreateFailure(kind, code, message)),
            HasMimeTypeFile: false,
            MimeTypeMatchesContainer: false,
            IsMimeTypeFileFirst: false,
            IsMimeTypeFileStored: false,
            HasSignatureFile: false,
            HasSinglePayloadFile: false,
            PayloadEntryName: null,
            SignatureEntryName: null);

    private static ValidationFailure CreateFailure(ValidationFailureKind kind, string code, string message) =>
        new(kind, code, message);

    private static SignatureDescriptor ToAsicDescriptor(SignatureDescriptor source) =>
        new(
            SignatureFormat.ASiC,
            source.Level,
            source.SigningCertificate,
            source.SigningTime,
            source.ValidationMaterial,
            source.SignatureAlgorithm,
            source.DigestAlgorithm);

    private static bool TryReadFirstLocalFileHeader(ReadOnlySpan<byte> buffer, out string? entryName, out ushort compressionMethod)
    {
        entryName = null;
        compressionMethod = ushort.MaxValue;

        if (buffer.Length < 30)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(buffer[..4]) != 0x04034B50)
        {
            return false;
        }

        compressionMethod = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(8, 2));
        var fileNameLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(26, 2));
        var extraFieldLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(28, 2));
        var requiredLength = 30 + fileNameLength + extraFieldLength;
        if (buffer.Length < requiredLength)
        {
            return false;
        }

        entryName = Encoding.UTF8.GetString(buffer.Slice(30, fileNameLength));
        return true;
    }

    private static string ReadUtf8(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
        return reader.ReadToEnd();
    }

    private static byte[] ReadAllBytes(ZipArchiveEntry entry)
    {
        using var source = entry.Open();
        using var target = new MemoryStream();
        source.CopyTo(target);
        return target.ToArray();
    }

    private sealed record ContainerInspection(
        bool HasMimeTypeFile,
        string? MimeTypeContent,
        bool IsMimeTypeFileFirst,
        bool IsMimeTypeFileStored,
        bool HasSignatureFile,
        bool HasSinglePayloadFile,
        string? PayloadEntryName,
        string? SignatureEntryName,
        byte[]? PayloadData,
        byte[]? SignatureData)
    {
        public ASiCSBaselineBVerificationResult ToResult(ValidationResult validation) =>
            new(
                validation,
                HasMimeTypeFile,
                string.Equals(MimeTypeContent, ContainerMediaType, StringComparison.Ordinal),
                IsMimeTypeFileFirst,
                IsMimeTypeFileStored,
                HasSignatureFile,
                HasSinglePayloadFile,
                PayloadEntryName,
                SignatureEntryName);
    }

    private sealed record StoredZipEntry(string Name, byte[] Data);

    private static class StoredZipContainerBuilder
    {
        public static byte[] Build(IReadOnlyList<StoredZipEntry> entries, DateTimeOffset timestamp)
        {
            ArgumentNullException.ThrowIfNull(entries);

            using var stream = new MemoryStream();
            var metadata = new List<ZipEntryMetadata>(entries.Count);
            foreach (var entry in entries)
            {
                metadata.Add(WriteLocalFileHeader(stream, entry, timestamp));
            }

            var centralDirectoryOffset = checked((uint)stream.Position);
            foreach (var entry in metadata)
            {
                WriteCentralDirectoryHeader(stream, entry);
            }

            var centralDirectorySize = checked((uint)stream.Position - centralDirectoryOffset);
            WriteEndOfCentralDirectory(stream, metadata.Count, centralDirectorySize, centralDirectoryOffset);
            return stream.ToArray();
        }

        private static ZipEntryMetadata WriteLocalFileHeader(Stream stream, StoredZipEntry entry, DateTimeOffset timestamp)
        {
            var headerOffset = checked((uint)stream.Position);
            var entryNameBytes = Encoding.UTF8.GetBytes(entry.Name);
            var (dosDate, dosTime) = ToDosTimestamp(timestamp);
            var crc32 = Crc32.Compute(entry.Data);
            var size = checked((uint)entry.Data.Length);

            WriteUInt32(stream, 0x04034B50);
            WriteUInt16(stream, 20);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, dosTime);
            WriteUInt16(stream, dosDate);
            WriteUInt32(stream, crc32);
            WriteUInt32(stream, size);
            WriteUInt32(stream, size);
            WriteUInt16(stream, checked((ushort)entryNameBytes.Length));
            WriteUInt16(stream, 0);
            stream.Write(entryNameBytes);
            stream.Write(entry.Data);

            return new ZipEntryMetadata(entry.Name, entryNameBytes, crc32, size, dosDate, dosTime, headerOffset);
        }

        private static void WriteCentralDirectoryHeader(Stream stream, ZipEntryMetadata entry)
        {
            WriteUInt32(stream, 0x02014B50);
            WriteUInt16(stream, 20);
            WriteUInt16(stream, 20);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, entry.DosTime);
            WriteUInt16(stream, entry.DosDate);
            WriteUInt32(stream, entry.Crc32);
            WriteUInt32(stream, entry.Size);
            WriteUInt32(stream, entry.Size);
            WriteUInt16(stream, checked((ushort)entry.EntryNameBytes.Length));
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt32(stream, 0);
            WriteUInt32(stream, entry.LocalHeaderOffset);
            stream.Write(entry.EntryNameBytes);
        }

        private static void WriteEndOfCentralDirectory(Stream stream, int entryCount, uint centralDirectorySize, uint centralDirectoryOffset)
        {
            WriteUInt32(stream, 0x06054B50);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, checked((ushort)entryCount));
            WriteUInt16(stream, checked((ushort)entryCount));
            WriteUInt32(stream, centralDirectorySize);
            WriteUInt32(stream, centralDirectoryOffset);
            WriteUInt16(stream, 0);
        }

        private static (ushort DosDate, ushort DosTime) ToDosTimestamp(DateTimeOffset timestamp)
        {
            var local = timestamp.UtcDateTime;
            var year = Math.Clamp(local.Year, 1980, 2107);
            var month = Math.Clamp(local.Month, 1, 12);
            var day = Math.Clamp(local.Day, 1, DateTime.DaysInMonth(year, month));
            var hour = Math.Clamp(local.Hour, 0, 23);
            var minute = Math.Clamp(local.Minute, 0, 59);
            var second = Math.Clamp(local.Second, 0, 59) / 2;

            var dosDate = (ushort)(((year - 1980) << 9) | (month << 5) | day);
            var dosTime = (ushort)((hour << 11) | (minute << 5) | second);
            return (dosDate, dosTime);
        }

        private static void WriteUInt16(Stream stream, ushort value)
        {
            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
            stream.Write(buffer);
        }

        private static void WriteUInt32(Stream stream, uint value)
        {
            Span<byte> buffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
            stream.Write(buffer);
        }

        private sealed record ZipEntryMetadata(
            string EntryName,
            byte[] EntryNameBytes,
            uint Crc32,
            uint Size,
            ushort DosDate,
            ushort DosTime,
            uint LocalHeaderOffset);
    }

    private static class Crc32
    {
        private static readonly uint[] Table = BuildTable();

        public static uint Compute(ReadOnlySpan<byte> data)
        {
            uint crc = 0xFFFFFFFF;
            foreach (var b in data)
            {
                crc = (crc >> 8) ^ Table[(crc ^ b) & 0xFF];
            }

            return ~crc;
        }

        private static uint[] BuildTable()
        {
            var table = new uint[256];
            for (uint i = 0; i < table.Length; i++)
            {
                uint value = i;
                for (var bit = 0; bit < 8; bit++)
                {
                    value = (value & 1) != 0
                        ? 0xEDB88320u ^ (value >> 1)
                        : value >> 1;
                }

                table[i] = value;
            }

            return table;
        }
    }
}
