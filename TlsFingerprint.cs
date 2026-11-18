using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

internal sealed record TlsFingerprint(string Ja3, string Ja3String, string Ja4, int CipherCount, int ExtensionCount);

internal static class TlsClientHelloFingerprint
{
    public static bool TryCreate(ReadOnlySpan<byte> record, out TlsFingerprint? fingerprint)
    {
        fingerprint = null;

        // Kestrel's .NET 10 callback supplies the TLS record wrapping the handshake.
        if (record.Length < 9 || record[0] != 22 || record[5] != 1)
            return false;

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(3, 2));
        var helloLength = ReadUInt24(record.Slice(6, 3));
        if (recordLength > record.Length - 5 || helloLength > recordLength - 4)
            return false; // This PoC reports only a complete, single-record ClientHello.

        var hello = record.Slice(9, helloLength);
        var offset = 0;
        if (!ReadU16(hello, ref offset, out var legacyVersion) || !Skip(hello, ref offset, 32)) return false;
        if (!ReadByte(hello, ref offset, out var sessionIdLength) || !Skip(hello, ref offset, sessionIdLength)) return false;
        if (!ReadU16(hello, ref offset, out var cipherBytesLength) || cipherBytesLength % 2 != 0 || !Take(hello, ref offset, cipherBytesLength, out var cipherBytes)) return false;
        var ciphers = ReadU16List(cipherBytes);
        if (!ReadByte(hello, ref offset, out var compressionLength) || !Skip(hello, ref offset, compressionLength)) return false;

        var extensions = new List<(ushort Id, ReadOnlyMemory<byte> Body)>();
        if (offset < hello.Length)
        {
            if (!ReadU16(hello, ref offset, out var extensionsLength) || !Take(hello, ref offset, extensionsLength, out var extensionBytes)) return false;
            var extensionOffset = 0;
            while (extensionOffset < extensionBytes.Length)
            {
                if (!ReadU16(extensionBytes, ref extensionOffset, out var id) ||
                    !ReadU16(extensionBytes, ref extensionOffset, out var length) ||
                    !Take(extensionBytes, ref extensionOffset, length, out var body)) return false;
                extensions.Add((id, body.ToArray()));
            }
        }

        if (offset != hello.Length) return false;
        var normalCiphers = ciphers.Where(x => !IsGrease(x)).ToList();
        var normalExtensions = extensions.Where(x => !IsGrease(x.Id)).ToList();
        var groups = ReadU16ExtensionList(extensions, 10);
        var pointFormats = ReadByteExtensionList(extensions, 11);

        var ja3String = string.Join(',',
            legacyVersion.ToString(),
            JoinDecimal(normalCiphers),
            JoinDecimal(normalExtensions.Select(x => x.Id)),
            JoinDecimal(groups),
            JoinDecimal(pointFormats));
        var ja3 = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(ja3String))).ToLowerInvariant();

        var negotiatedOfferVersion = ReadSupportedVersion(extensions) ?? legacyVersion;
        var ja4Version = FormatTlsVersion(negotiatedOfferVersion);
        var hasSni = extensions.Any(x => x.Id == 0);
        var alpn = ReadFirstAlpn(extensions);
        var alpnPart = alpn is { Length: > 0 } ? FirstLastAlnum(alpn) : "00";
        var ja4a = $"t{ja4Version}{(hasSni ? 'd' : 'i')}{Count2(normalCiphers.Count)}{Count2(normalExtensions.Count)}{alpnPart}";

        var cipherHashInput = string.Join(',', normalCiphers.Select(Hex4).OrderBy(x => x, StringComparer.Ordinal));
        var ja4b = Sha256Prefix(cipherHashInput);
        var extensionIds = normalExtensions.Select(x => x.Id).Where(x => x is not 0 and not 16)
            .Select(Hex4).OrderBy(x => x, StringComparer.Ordinal);
        var signatureAlgorithms = ReadU16ExtensionList(extensions, 13).Select(Hex4);
        var ja4cInput = string.Join(',', extensionIds) + "_" + string.Join(',', signatureAlgorithms);
        var ja4c = Sha256Prefix(ja4cInput);

        fingerprint = new TlsFingerprint(ja3, ja3String, $"{ja4a}_{ja4b}_{ja4c}", normalCiphers.Count, normalExtensions.Count);
        return true;
    }

    private static ushort? ReadSupportedVersion(List<(ushort Id, ReadOnlyMemory<byte> Body)> extensions)
    {
        var body = extensions.FirstOrDefault(x => x.Id == 43).Body.Span;
        if (body.Length < 3 || body[0] > body.Length - 1 || body[0] % 2 != 0) return null;
        ushort? highest = null;
        for (var i = 1; i < 1 + body[0]; i += 2)
        {
            var version = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(i, 2));
            if (!IsGrease(version) && (highest is null || version > highest)) highest = version;
        }
        return highest;
    }

    private static List<ushort> ReadU16ExtensionList(List<(ushort Id, ReadOnlyMemory<byte> Body)> extensions, ushort id)
    {
        var body = extensions.FirstOrDefault(x => x.Id == id).Body.Span;
        if (body.Length < 2) return [];
        var length = BinaryPrimitives.ReadUInt16BigEndian(body[..2]);
        if (length % 2 != 0 || length > body.Length - 2) return [];
        var result = new List<ushort>(length / 2);
        for (var i = 2; i < 2 + length; i += 2)
        {
            var value = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(i, 2));
            if (!IsGrease(value)) result.Add(value);
        }
        return result;
    }

    private static List<byte> ReadByteExtensionList(List<(ushort Id, ReadOnlyMemory<byte> Body)> extensions, ushort id)
    {
        var body = extensions.FirstOrDefault(x => x.Id == id).Body.Span;
        if (body.Length < 1 || body[0] > body.Length - 1) return [];
        return body.Slice(1, body[0]).ToArray().ToList();
    }

    private static byte[]? ReadFirstAlpn(List<(ushort Id, ReadOnlyMemory<byte> Body)> extensions)
    {
        var body = extensions.FirstOrDefault(x => x.Id == 16).Body.Span;
        if (body.Length < 3) return null;
        var listLength = BinaryPrimitives.ReadUInt16BigEndian(body[..2]);
        var nameLength = body[2];
        if (listLength > body.Length - 2 || nameLength > body.Length - 3) return null;
        return body.Slice(3, nameLength).ToArray();
    }

    private static string FirstLastAlnum(byte[] value)
    {
        static bool IsAsciiAlnum(byte b) => b is >= (byte)'0' and <= (byte)'9' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z';
        var first = value[0];
        var last = value[^1];
        return $"{(IsAsciiAlnum(first) ? ((char)first).ToString().ToLowerInvariant() : first.ToString("x2"))}" +
               $"{(IsAsciiAlnum(last) ? ((char)last).ToString().ToLowerInvariant() : last.ToString("x2"))}";
    }

    private static string FormatTlsVersion(ushort version) => version switch
    {
        0x0304 => "13", 0x0303 => "12", 0x0302 => "11", 0x0301 => "10", 0x0300 => "s3", 0x0002 => "s2", _ => "00"
    };

    private static string Count2(int count) => Math.Min(count, 99).ToString("D2");
    private static string Hex4(ushort value) => value.ToString("x4");
    private static string Sha256Prefix(string value) => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value))).ToLowerInvariant()[..12];
    private static string JoinDecimal(IEnumerable<ushort> values) => string.Join('-', values.Select(x => x.ToString()));
    private static string JoinDecimal(IEnumerable<byte> values) => string.Join('-', values.Select(x => x.ToString()));
    private static List<ushort> ReadU16List(ReadOnlySpan<byte> bytes)
    {
        var values = new List<ushort>(bytes.Length / 2);
        for (var i = 0; i < bytes.Length; i += 2) values.Add(BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(i, 2)));
        return values;
    }
    private static bool IsGrease(ushort value) => (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff);
    private static int ReadUInt24(ReadOnlySpan<byte> b) => (b[0] << 16) | (b[1] << 8) | b[2];
    private static bool ReadU16(ReadOnlySpan<byte> b, ref int p, out ushort value)
    {
        value = 0;
        if (p + 2 > b.Length) return false;
        value = BinaryPrimitives.ReadUInt16BigEndian(b.Slice(p, 2)); p += 2; return true;
    }
    private static bool ReadByte(ReadOnlySpan<byte> b, ref int p, out byte value)
    {
        value = 0;
        if (p >= b.Length) return false;
        value = b[p++]; return true;
    }
    private static bool Skip(ReadOnlySpan<byte> b, ref int p, int length)
    {
        if (length < 0 || p + length > b.Length) return false;
        p += length; return true;
    }
    private static bool Take(ReadOnlySpan<byte> b, ref int p, int length, out ReadOnlySpan<byte> value)
    {
        value = default;
        if (length < 0 || p + length > b.Length) return false;
        value = b.Slice(p, length); p += length; return true;
    }
}
