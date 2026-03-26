using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

static class Program
{
    private static readonly HashSet<string> OutputFiles = new(StringComparer.OrdinalIgnoreCase);

    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine(
                "\"Unquarantine.exe\"\n" +
                "Usage: \"Unquarantine.exe\" <filename-or-directory>\n" +
                "Example: \"Unquarantine.exe\" \"C:\\path\\to\\DefenderQuarantine\"\n" +
                "Behavior: recursively scans and writes decrypted artifacts as *.recovered next to inputs (plus an optional *.recovered.name.txt sidecar when Defender metadata contains a filename-like string)."
            );
            return 2;
        }

        var target = args[0];
        if (Directory.Exists(target))
        {
            ScanDirectory(target);
            return 0;
        }

        if (File.Exists(target))
        {
            ProcessOneFile(target);
            return 0;
        }

        Console.Error.WriteLine($"Error: Don't know what to do with '{target}'");
        return 2;
    }

    private static void ScanDirectory(string dir)
    {
        Console.Error.WriteLine($"Processing  directory: '{NormalizeDisplayPath(dir)}'");

        IEnumerable<string> entries;
        try
        {
            entries = Directory.EnumerateFileSystemEntries(dir).OrderBy(p => p, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($" -> Can't read directory: {ex.Message}");
            return;
        }

        foreach (var entry in entries)
        {
            try
            {
                if (Directory.Exists(entry))
                {
                    ScanDirectory(entry);
                }
                else if (File.Exists(entry))
                {
                    ProcessOneFile(entry);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($" -> Error processing '{NormalizeDisplayPath(entry)}': {ex.Message}");
            }
        }
    }

    private static void ProcessOneFile(string filePath)
    {
        filePath = NormalizePath(filePath);

        if (OutputFiles.Contains(filePath))
            return;

        // Skip "out_XXXXXXXX_XXXXXXXX" paths similar to perl guard
        if (filePath.Contains("out_", StringComparison.OrdinalIgnoreCase))
        {
            // keep this loose; we only need to avoid re-processing our own outputs
            if (filePath.IndexOf("_", filePath.IndexOf("out_", StringComparison.OrdinalIgnoreCase) + 4, StringComparison.OrdinalIgnoreCase) >= 0)
                return;
        }

        var ext = Path.GetExtension(filePath);
        if (ext.Equals(".log", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".rpt", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".db", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".db-wal", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".csv", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // The tool writes extracted artifacts as *.out/*.met/*.recovered.
        // If we re-process those, we end up decrypting output files again and generating nested outputs.
        if (ext.Equals(".out", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".met", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".recovered", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (filePath.EndsWith(".name.txt", StringComparison.OrdinalIgnoreCase))
            return;

        Console.Error.WriteLine($"Processing file: '{NormalizeDisplayPath(filePath)}'");

        FileInfo fi;
        try
        {
            fi = new FileInfo(filePath);
        }
        catch
        {
            Console.Error.WriteLine(" -> Can't be found! (check attributes/access rights)");
            return;
        }

        if (!fi.Exists)
        {
            Console.Error.WriteLine(" -> Can't be found! (check attributes/access rights)");
            return;
        }

        if (fi.Length == 0)
        {
            Console.Error.WriteLine(" -> Skipping cuz it's empty");
            return;
        }

        byte[] data;
        try
        {
            data = File.ReadAllBytes(filePath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($" -> Error reading: {ex.Message}");
            return;
        }

        if (data.LongLength != fi.Length)
        {
            Console.Error.WriteLine(" -> Skipping cuz something funny happened during data reading (investigate)");
            return;
        }

        // Defender Mac: perl checks GUID-ish name match anywhere in path
        if (LooksLikeGuidInPath(filePath))
        {
            ExtractDefenderMac(filePath, data, ofs: 0);
            return;
        }

        // Defender PC: perl checks encrypted stream header bytes
        if (data.Length >= 2)
        {
            if ((data[0] == 0xD3 && data[1] == 0x45) || (data[0] == 0x0B && data[1] == 0xAD))
            {
                ExtractDefender(filePath, data, fi.Length);
                return;
            }
        }

        // Symantec ccSubSDK {GUID} Files
        if (LooksLikeGuidWrappedInBracesFilename(filePath))
        {
            ExtractSymCcSubSDK(filePath, data);
            return;
        }

        // Generic X-RAY scan (find embedded encrypted payloads)
        XrayScan(filePath, data);
    }

    private static void XrayScan(string filePath, byte[] data)
    {
        int datalen = data.Length;
        if (datalen < 4)
            return;

        if (data[0] == (byte)'M' && data[1] == (byte)'Z')
        {
            // Perl skips x-ray scan for files already starting with "MZ"
            return;
        }

        Console.Error.WriteLine($"    Attempting x-ray scan ({datalen} bytes)");

        int cnt = 0;
        double progress = 0;
        double lastprogress = 0;
        double progressDelta = 100.0 / datalen;

        for (int ofs = 0; ofs < datalen; ofs++)
        {
            byte b0 = data[ofs];
            byte b1 = (ofs + 1 < datalen) ? data[ofs + 1] : (byte)0;

            if (progress != lastprogress)
            {
                Console.Error.Write($"{(int)progress}%\r");
            }

            // X-RAY key discovery: if xor(first, second) == 0x17, guess key
            if ((byte)(b0 ^ b1) == 0x17)
            {
                byte key = (byte)(b0 ^ 0x4D);
                if ((byte)(b1 ^ key) == 0x5A)
                {
                    // Check decrypted chunk: must start with "MZ" and contain "PE\0\0"
                    if (LooksLikeMzPeDecryptedChunk(data, ofs, key))
                    {
                        cnt += ExtractData(filePath, data, ofs, datalen - ofs, key, flag: 0);
                    }
                }
            }

            lastprogress = progress;
            progress += progressDelta;
        }

        if (cnt == 0)
            Console.Error.WriteLine(" -> Nothing found via X-RAY");
        else
            Console.Error.WriteLine($" -> {cnt} potential file(s) found via X-RAY");
    }

    private static bool LooksLikeMzPeDecryptedChunk(byte[] data, int ofs, byte key)
    {
        int chunkLen = Math.Min(16384, data.Length - ofs);
        if (chunkLen < 4) return false;

        // Check MZ at start
        if ((byte)(data[ofs + 0] ^ key) != (byte)'M') return false;
        if ((byte)(data[ofs + 1] ^ key) != (byte)'Z') return false;

        // Search for "PE\0\0" anywhere after the initial "MZ"
        for (int i = 2; i + 3 < chunkLen; i++)
        {
            if ((byte)(data[ofs + i + 0] ^ key) == (byte)'P' &&
                (byte)(data[ofs + i + 1] ^ key) == (byte)'E' &&
                (byte)(data[ofs + i + 2] ^ key) == 0x00 &&
                (byte)(data[ofs + i + 3] ^ key) == 0x00)
            {
                return true;
            }
        }
        return false;
    }

    private static int ExtractData(string filePath, byte[] data, int ofs, int size, byte key, int flag)
    {
        // Perl: $file.'.%08d.%02X.out' where $ofs is decimal and $key is 2-digit hex.
        string newfilename = $"{filePath}.{ofs:D8}.{key:X2}.out";

        byte[] segment = new byte[size];
        for (int i = 0; i < size; i++)
        {
            segment[i] = (byte)(data[ofs + i] ^ key);
        }

        if (LooksLikeMzPe(segment))
        {
            Console.Error.WriteLine($" -> '{NormalizeDisplayPath(newfilename)}' - Possible PE");
            Console.Error.WriteLine($" -> ofs='{ofs}' ({ofs:X8}), key = 0x{key:X2} ({key})");
            WriteFile(newfilename, segment);
            return 1;
        }
        else if (LooksLikeArchive(segment))
        {
            Console.Error.WriteLine($" -> '{NormalizeDisplayPath(newfilename)}' - Possible Archive");
            Console.Error.WriteLine($" -> ofs='{ofs}' ({ofs:X8}), key = 0x{key:X2} ({key})");
            WriteFile(newfilename, segment);
            return 1;
        }
        else if (LooksLikePdf(segment))
        {
            Console.Error.WriteLine($" -> '{NormalizeDisplayPath(newfilename)}' - Possible PDF");
            Console.Error.WriteLine($" -> ofs='{ofs}' ({ofs:X8}), key = 0x{key:X2} ({key})");
            WriteFile(newfilename, segment);
            return 1;
        }
        else if (flag == 1)
        {
            Console.Error.WriteLine($" -> '{NormalizeDisplayPath(newfilename)}' - Decrypted data");
            Console.Error.WriteLine($" -> ofs='{ofs}' ({ofs:X8}), key = 0x{key:X2} ({key})");
            WriteFile(newfilename, segment);
            return 1;
        }

        return 0;
    }

    private static bool LooksLikeMzPe(byte[] newdata)
    {
        if (newdata.Length < 4) return false;
        if (newdata[0] != (byte)'M' || newdata[1] != (byte)'Z') return false;

        // Perl check: /^MZ.+PE\x00\x00/si requires at least 1 byte between 'Z' and 'P' ('.+')
        for (int i = 3; i + 3 < newdata.Length; i++)
        {
            if (newdata[i] == (byte)'P' &&
                newdata[i + 1] == (byte)'E' &&
                newdata[i + 2] == 0x00 &&
                newdata[i + 3] == 0x00)
                return true;
        }
        return false;
    }

    private static bool LooksLikeArchive(byte[] d)
    {
        // Perl: /^(PK\x03\x04|Cr24|Rar!|\xCA\xFE\xBA\xBE|CAB|SZDD)/si
        // We treat ASCII letter variants case-insensitively for the named magic strings.
        if (d.Length < 4) return false;

        if (d.Length >= 4 && d[0] == 0x50 && d[1] == 0x4B && d[2] == 0x03 && d[3] == 0x04) return true; // PK..

        if (d.Length >= 4 && d[0] == (byte)'C' && (d[1] == (byte)'r' || d[1] == (byte)'R') && d[2] == (byte)'2' && d[3] == (byte)'4') return true; // Cr24

        if (d.Length >= 4 && (d[0] == (byte)'R' || d[0] == (byte)'r') && (d[1] == (byte)'a' || d[1] == (byte)'A') && (d[2] == (byte)'r' || d[2] == (byte)'R') && d[3] == (byte)'!') return true; // Rar!

        if (d.Length >= 4 && d[0] == 0xCA && d[1] == 0xFE && d[2] == 0xBA && d[3] == 0xBE) return true; // CAFEBABE

        if (d.Length >= 3 && d[0] == (byte)'C' && (d[1] == (byte)'A' || d[1] == (byte)'a') && (d[2] == (byte)'B' || d[2] == (byte)'b')) return true; // CAB

        if (d.Length >= 4 &&
            d[0] == (byte)'S' &&
            (d[1] == (byte)'Z' || d[1] == (byte)'z') &&
            (d[2] == (byte)'D' || d[2] == (byte)'d') &&
            (d[3] == (byte)'D' || d[3] == (byte)'d')) return true; // SZDD

        return false;
    }

    private static bool LooksLikePdf(byte[] d)
    {
        // Perl: /^\%PDF/si  => '%' 'P' 'D' 'F'
        if (d.Length < 4) return false;
        return d[0] == 0x25 &&
               (d[1] == (byte)'P' || d[1] == (byte)'p') &&
               (d[2] == (byte)'D' || d[2] == (byte)'d') &&
               (d[3] == (byte)'F' || d[3] == (byte)'f');
    }

    // Generic carving routine inspired by Perl's `carve`.
    // Note: currently unused because we haven't ported the vendor extractor paths
    // that call it (e.g. Symantec ccSubSDK).
    private static void Carve(string filename)
    {
        const int maxSizeRead = 1024 * 1024;
        const int minExtractSize = 128;

        var magic = new Dictionary<string, byte[]> (StringComparer.Ordinal)
        {
            ["BMP"] = new byte[] { (byte)'B', (byte)'M' },
            ["JPEG"] = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, // close enough for dexray's usage
            ["PNG"] = new byte[] { 0x89, (byte)'P', (byte)'N', (byte)'G' },
            ["CLASS"] = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE },
            ["CAB"] = Encoding.ASCII.GetBytes("CAB"),
            ["SZDD"] = Encoding.ASCII.GetBytes("SZDD"),
            ["Rar"] = Encoding.ASCII.GetBytes("Rar!"),
            ["PE"] = new byte[] { (byte)'M', (byte)'Z' },
            ["PHP"] = Encoding.ASCII.GetBytes("<?php"),
            ["LUA"] = Encoding.ASCII.GetBytes("\x1bLua"),
            ["XMP"] = Encoding.ASCII.GetBytes("<?xpacket begin"),
            ["Crx"] = Encoding.ASCII.GetBytes("Cr24"),
            ["rtf"] = Encoding.ASCII.GetBytes("{\\rtf"),
            ["ZIP"] = Encoding.ASCII.GetBytes("PK\x03\x04"),
        };

        var fi = new FileInfo(filename);
        if (!fi.Exists)
            return;

        long fileSize = fi.Length;
        if (fileSize <= 1)
            return;

        using var fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read);

        fs.Seek(1, SeekOrigin.Begin); // Perl skips first byte
        int toRead = (int)Math.Min(maxSizeRead, fileSize - 1);
        var raw = new byte[toRead];
        int read = fs.Read(raw, 0, toRead);
        if (read <= 0) return;

        // Replace CR/LF with '*' like Perl (skip exact value in bytes search)
        for (int i = 0; i < read; i++)
        {
            if (raw[i] == 0x0D || raw[i] == 0x0A)
                raw[i] = (byte)'*';
        }

        foreach (var kvp in magic)
        {
            string tag = kvp.Key;
            byte[] sig = kvp.Value;
            int sigLen = sig.Length;
            if (sigLen == 0) continue;

            var offsets = new List<int>();
            for (int i = 0; i + sigLen <= read; i++)
            {
                bool ok = true;
                for (int j = 0; j < sigLen; j++)
                {
                    if (raw[i + j] != sig[j]) { ok = false; break; }
                }
                if (ok)
                    offsets.Add(i);
            }

            if (offsets.Count == 0)
                continue;

            // Extract each carved blob using consecutive offsets.
            offsets.Sort();
            string sanitizedBase = filename;
            sanitizedBase = sanitizedBase.TrimStart('.', '/', '\\');
            sanitizedBase = sanitizedBase.Replace('\\', '_').Replace('/', '_');

            for (int k = 0; k < offsets.Count; k++)
            {
                long ofsInFile = offsets[k] + 1; // +1 due to Seek(1)
                long nextOfs = (k + 1 < offsets.Count) ? offsets[k + 1] + 1 : fileSize;
                long size = nextOfs - ofsInFile;
                if (size < minExtractSize)
                    continue;

                byte[] carved = new byte[size];
                fs.Seek(ofsInFile, SeekOrigin.Begin);
                int r = 0;
                while (r < size)
                {
                    int got = fs.Read(carved, r, (int)(size - r));
                    if (got <= 0) break;
                    r += got;
                }

                string outName =
                    $"{sanitizedBase}_{ofsInFile:X8}_{size:X8}.{tag}";
                WriteFile(outName, carved);

                if (tag.Equals("PHP", StringComparison.Ordinal))
                    break;
            }
        }
    }

    // Symantec ccSubSDK decryption:
    // Perl:
    //   my $dec = blowfishit(substr($data,32,length($data)-32), substr($data,16,16), 1);
    //   writefile ($file.'.%08d_Symantec_ccSubSDK.out',$ofs, $dec);
    private static void ExtractSymCcSubSDK(string filePath, byte[] data)
    {
        if (data.Length < 32)
            return;

        const int ofs = 0;
        var outPath = $"{filePath}.{ofs:00000000}_Symantec_ccSubSDK.out";

        // Key is 16 bytes at offset 16
        var key = new byte[16];
        Buffer.BlockCopy(data, 16, key, 0, 16);

        // Ciphertext starts at offset 32
        var encLen = data.Length - 32;
        var enc = new byte[encLen];
        Buffer.BlockCopy(data, 32, enc, 0, encLen);

        var dec = BlowfishIt(enc, key, swap: 1);
        Console.Error.WriteLine($" -> '{NormalizeDisplayPath(outPath)}' - Symantec_ccSubSDK File");
        WriteFile(outPath, dec);

        // Perl carves embedded objects from the decrypted output.
        Carve(outPath);

        // Metadata parsing (parsesym) is non-trivial; create placeholder for now.
        var metaPath = $"{filePath}.{ofs:00000000}_Symantec_ccSubSDK.met";
        try
        {
            File.WriteAllText(metaPath, string.Empty, Encoding.UTF8);
        }
        catch
        {
            // ignore
        }
    }

    private static byte[] BlowfishIt(byte[] data, byte[] key, int swap)
    {
        // Perl blowfishit:
        //   while ($data=~/(.{8})/sg) { $d=block; if swap: byteswap each 32-bit word; $d=bf->decrypt($d); if swap: same swap; $dec.=$d; }
        int blocks = data.Length / 8; // ignore trailing remainder, like perl regex (.{8})
        if (blocks <= 0)
            return Array.Empty<byte>();

        var engine = new BlowfishEngine();
        engine.Init(false, new KeyParameter(key)); // decrypt

        var output = new byte[blocks * 8];
        var block = new byte[8];
        var decrypted = new byte[8];

        for (int b = 0; b < blocks; b++)
        {
            Buffer.BlockCopy(data, b * 8, block, 0, 8);

            if (swap == 1)
                SwapWords32Endian(block, 0);

            engine.ProcessBlock(block, 0, decrypted, 0);

            if (swap == 1)
                SwapWords32Endian(decrypted, 0);

            Buffer.BlockCopy(decrypted, 0, output, b * 8, 8);
        }

        return output;
    }

    // Convert each 32-bit word from little-endian bytes to big-endian bytes (byteswap within the word).
    // This matches Perl: pack("N",unpack("I",...)) on a little-endian platform.
    private static void SwapWords32Endian(byte[] buf, int offset)
    {
        uint w1 = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(offset + 0, 4));
        uint w2 = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(offset + 4, 4));

        buf[offset + 0] = (byte)(w1 >> 24);
        buf[offset + 1] = (byte)(w1 >> 16);
        buf[offset + 2] = (byte)(w1 >> 8);
        buf[offset + 3] = (byte)(w1 >> 0);

        buf[offset + 4] = (byte)(w2 >> 24);
        buf[offset + 5] = (byte)(w2 >> 16);
        buf[offset + 6] = (byte)(w2 >> 8);
        buf[offset + 7] = (byte)(w2 >> 0);
    }

    private static bool LooksLikeGuidWrappedInBracesFilename(string filePath)
    {
        var name = Path.GetFileName(filePath);
        // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} => 38 chars
        if (name.Length != 38)
            return false;
        if (name[0] != '{' || name[37] != '}')
            return false;

        int[] hyphens = { 9, 14, 19, 24 };
        foreach (var pos in hyphens)
            if (name[pos] != '-') return false;

        // digits ranges: 1-8, 10-13, 15-18, 20-23, 25-36
        for (int i = 1; i <= 8; i++) if (!IsHex(name[i])) return false;
        for (int i = 10; i <= 13; i++) if (!IsHex(name[i])) return false;
        for (int i = 15; i <= 18; i++) if (!IsHex(name[i])) return false;
        for (int i = 20; i <= 23; i++) if (!IsHex(name[i])) return false;
        for (int i = 25; i <= 36; i++) if (!IsHex(name[i])) return false;

        return true;
    }

    private static void ExtractDefenderMac(string filePath, byte[] data, int ofs)
    {
        var outPath = $"{filePath}.{ofs:00000000}_defender_mac.recovered";
        var dec = XorByte(data, 0x25);

        Console.Error.WriteLine($" -> '{NormalizeDisplayPath(outPath)}' - Microsoft Defender for Mac File");
        Console.Error.WriteLine($" -> ofs='{ofs}' ({ofs:X8})");

        WriteFile(outPath, dec);
    }

    private static void ExtractDefender(string filePath, byte[] data, long originalFileSize)
    {
        if (data.Length < 0x3C)
            return;

        // Perl's extract_defender is called with arguments:
        // extract_defender($file, $data, 0x00000000, $filesize)
        // so inside extract_defender, the parameter named $ofs ends up being the original file size.
        long ofsParam = originalFileSize;

        const int hdrlen = 0x3C;

        var key = DefenderRc4Key();

        var hdrEnc = data.AsSpan(0, hdrlen).ToArray();
        var hdr = Rc4Transform(hdrEnc, key);

        if (hdr.Length >= 4 && hdr[0] == 0xDB && hdr[1] == 0xE8 && hdr[2] == 0xC5 && hdr[3] == 0x01)
        {
            // Header+two decrypted segments (metadata + content)
            if (data.Length < hdrlen)
                return;

            var dataTail = data.AsSpan(hdrlen).ToArray();

            uint len1 = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(0x28, 4));
            uint len2 = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(0x2C, 4));

            if (len1 > dataTail.Length || len2 > dataTail.Length || (long)len1 + (long)len2 > dataTail.Length)
                return;

            var dec1Enc = dataTail.AsSpan(0, (int)len1).ToArray();
            var dec1 = Rc4Transform(dec1Enc, key);

            var remaining = dataTail.AsSpan((int)len1).ToArray();
            var dec2Enc = remaining.AsSpan(0, (int)len2).ToArray();
            var dec2 = Rc4Transform(dec2Enc, key);

            var output = new byte[hdrlen + dec1.Length + dec2.Length];
            Buffer.BlockCopy(hdr, 0, output, 0, hdrlen);
            Buffer.BlockCopy(dec1, 0, output, hdrlen, dec1.Length);
            Buffer.BlockCopy(dec2, 0, output, hdrlen + dec1.Length, dec2.Length);

            var outPath = $"{filePath}.{ofsParam:D8}_defender.recovered";
            Console.Error.WriteLine($" -> '{NormalizeDisplayPath(outPath)}' - Defender File");
            Console.Error.WriteLine($" -> ofs='{ofsParam}' ({ofsParam:X8})");
            WriteFile(outPath, output);
            WriteNameSidecarIfFound(outPath, dec1);
        }
        else
        {
            // Whole-buffer decrypt, then slice to embedded payload
            var decAll = Rc4Transform(data, key);

            uint ofsComputed = 0x28u + BinaryPrimitives.ReadUInt32LittleEndian(decAll.AsSpan(0x08, 4));
            uint filesize = BinaryPrimitives.ReadUInt32LittleEndian(decAll.AsSpan((int)ofsComputed - 0xC, 4));

            if (ofsComputed > decAll.Length || (long)ofsComputed + (long)filesize > decAll.Length)
                return;

            var outPath = $"{filePath}.{ofsComputed:D8}_Defender.recovered";
            Console.Error.WriteLine($" -> '{NormalizeDisplayPath(outPath)}' - Defender File");
            Console.Error.WriteLine($" -> ofs='{ofsComputed}' ({ofsComputed:X8})");

            var payload = decAll.AsSpan((int)ofsComputed, (int)filesize).ToArray();
            WriteFile(outPath, payload);
            WriteNameSidecarIfFound(outPath, payload);
        }
    }

    private static byte[] DefenderRc4Key()
    {
        // Extracted directly from DeXRAY.pl (extract_defender -> my $key = "...").
        return new byte[]
        {
            0x1E,0x87,0x78,0x1B,0x8D,0xBA,0xA8,0x44,0xCE,0x69,0x70,0x2C,0x0C,0x78,0xB7,0x86,
            0xA3,0xF6,0x23,0xB7,0x38,0xF5,0xED,0xF9,0xAF,0x83,0x53,0x0F,0xB3,0xFC,0x54,0xFA,
            0xA2,0x1E,0xB9,0xCF,0x13,0x31,0xFD,0x0F,0x0D,0xA9,0x54,0xF6,0x87,0xCB,0x9E,0x18,
            0x27,0x96,0x97,0x90,0x0E,0x53,0xFB,0x31,0x7C,0x9C,0xBC,0xE4,0x8E,0x23,0xD0,0x53,
            0x71,0xEC,0xC1,0x59,0x51,0xB8,0xF3,0x64,0x9D,0x7C,0xA3,0x3E,0xD6,0x8D,0xC9,0x04,
            0x7E,0x82,0xC9,0xBA,0xAD,0x97,0x99,0xD0,0xD4,0x58,0xCB,0x84,0x7C,0xA9,0xFF,0xBE,
            0x3C,0x8A,0x77,0x52,0x33,0x55,0x7D,0xDE,0x13,0xA8,0xB1,0x40,0x87,0xCC,0x1B,0xC8,
            0xF1,0x0F,0x6E,0xCD,0xD0,0x83,0xA9,0x59,0xCF,0xF8,0x4A,0x9D,0x1D,0x50,0x75,0x5E,
            0x3E,0x19,0x18,0x18,0xAF,0x23,0xE2,0x29,0x35,0x58,0x76,0x6D,0x2C,0x07,0xE2,0x57,
            0x12,0xB2,0xCA,0x0B,0x53,0x5E,0xD8,0xF6,0xC5,0x6C,0xE7,0x3D,0x24,0xBD,0xD0,0x29,
            0x17,0x71,0x86,0x1A,0x54,0xB4,0xC2,0x85,0xA9,0xA3,0xDB,0x7A,0xCA,0x6D,0x22,0x4A,
            0xEA,0xCD,0x62,0x1D,0xB9,0xF2,0xA2,0x2E,0xD1,0xE9,0xE1,0x1D,0x75,0xBE,0xD7,0xDC,
            0x0E,0xCB,0x0A,0x8E,0x68,0xA2,0xFF,0x12,0x63,0x40,0x8D,0xC8,0x08,0xDF,0xFD,0x16,
            0x4B,0x11,0x67,0x74,0xCD,0x0B,0x9B,0x8D,0x05,0x41,0x1E,0xD6,0x26,0x2E,0x42,0x9B,
            0xA4,0x95,0x67,0x6B,0x83,0x98,0xDB,0x2F,0x35,0xD3,0xC1,0xB9,0xCE,0xD5,0x26,0x36,
            0xF2,0x76,0x5E,0x1A,0x95,0xCB,0x7C,0xA4,0xC3,0xDD,0xAB,0xDD,0xBF,0xF3,0x82,0x53,
        };
    }

    private static byte[] Rc4Transform(byte[] input, byte[] key)
    {
        // RC4 (KSA + PRGA). Decrypt/encrypt are identical for stream ciphers.
        var s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 0xFF;
            (s[i], s[j]) = (s[j], s[i]);
        }

        int iIndex = 0;
        j = 0;
        var output = new byte[input.Length];
        for (int k = 0; k < input.Length; k++)
        {
            iIndex = (iIndex + 1) & 0xFF;
            j = (j + s[iIndex]) & 0xFF;
            (s[iIndex], s[j]) = (s[j], s[iIndex]);
            int rnd = s[(s[iIndex] + s[j]) & 0xFF];
            output[k] = (byte)(input[k] ^ rnd);
        }

        return output;
    }

    private static byte[] XorByte(byte[] data, byte key)
    {
        var output = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            output[i] = (byte)(data[i] ^ key);
        return output;
    }

    private static void WriteFile(string path, byte[] data)
    {
        OutputFiles.Add(NormalizePath(path));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, data);
    }

    private static bool LooksLikeGuidInPath(string path)
    {
        // Perl: if ($file=~/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i)
        // We'll do a quick scan without regex allocations.
        ReadOnlySpan<char> s = path.AsSpan();
        for (int i = 0; i + 36 <= s.Length; i++)
        {
            if (IsHex(s[i + 0]) && IsHex(s[i + 1]) && IsHex(s[i + 2]) && IsHex(s[i + 3]) &&
                IsHex(s[i + 4]) && IsHex(s[i + 5]) && IsHex(s[i + 6]) && IsHex(s[i + 7]) &&
                s[i + 8] == '-' &&
                IsHex(s[i + 9]) && IsHex(s[i + 10]) && IsHex(s[i + 11]) && IsHex(s[i + 12]) &&
                s[i + 13] == '-' &&
                IsHex(s[i + 14]) && IsHex(s[i + 15]) && IsHex(s[i + 16]) && IsHex(s[i + 17]) &&
                s[i + 18] == '-' &&
                IsHex(s[i + 19]) && IsHex(s[i + 20]) && IsHex(s[i + 21]) && IsHex(s[i + 22]) &&
                s[i + 23] == '-' &&
                IsHex(s[i + 24]) && IsHex(s[i + 25]) && IsHex(s[i + 26]) && IsHex(s[i + 27]) &&
                IsHex(s[i + 28]) && IsHex(s[i + 29]) && IsHex(s[i + 30]) && IsHex(s[i + 31]) &&
                IsHex(s[i + 32]) && IsHex(s[i + 33]) && IsHex(s[i + 34]) && IsHex(s[i + 35]))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsHex(char c) =>
        (c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F');

    private static readonly Regex NameTokenRegex = new(
        @"[A-Za-z0-9][A-Za-z0-9._-]{1,254}\.[A-Za-z0-9]{2,8}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant
    );

    private static void WriteNameSidecarIfFound(string recoveredPath, byte[] metadataSource)
    {
        var candidate = TryRecoverNameCandidate(metadataSource);
        if (string.IsNullOrWhiteSpace(candidate))
            return;

        var sidecar = recoveredPath + ".name.txt";
        try
        {
            File.WriteAllText(sidecar, candidate, Encoding.UTF8);
            Console.Error.WriteLine($" -> '{NormalizeDisplayPath(sidecar)}' - Recovered name sidecar");
        }
        catch
        {
            // best effort only
        }
    }

    private static string? TryRecoverNameCandidate(byte[] source)
    {
        string? best = null;
        int bestScore = -1;

        foreach (Match m in NameTokenRegex.Matches(ExtractAsciiLikeText(source)))
        {
            var token = m.Value;
            var score = ScoreNameToken(token);
            if (score > bestScore)
            {
                best = token;
                bestScore = score;
            }
        }

        foreach (Match m in NameTokenRegex.Matches(ExtractUtf16LeLikeText(source)))
        {
            var token = m.Value;
            var score = ScoreNameToken(token);
            if (score > bestScore)
            {
                best = token;
                bestScore = score;
            }
        }

        return best;
    }

    private static int ScoreNameToken(string token)
    {
        int score = Math.Min(120, token.Length);
        var ext = Path.GetExtension(token);
        if (!string.IsNullOrWhiteSpace(ext))
            score += 20;
        if (token.Any(char.IsDigit))
            score += 8;
        return score;
    }

    private static string ExtractAsciiLikeText(byte[] source)
    {
        var chars = new char[source.Length];
        for (int i = 0; i < source.Length; i++)
        {
            byte b = source[i];
            chars[i] = (b >= 0x20 && b <= 0x7E) ? (char)b : ' ';
        }
        return new string(chars);
    }

    private static string ExtractUtf16LeLikeText(byte[] source)
    {
        if (source.Length < 2)
            return string.Empty;

        var sb = new StringBuilder(source.Length / 2);
        for (int i = 0; i + 1 < source.Length; i += 2)
        {
            ushort v = (ushort)(source[i] | (source[i + 1] << 8));
            char c = (char)v;
            if (c >= 0x20 && c <= 0x7E)
                sb.Append(c);
            else
                sb.Append(' ');
        }
        return sb.ToString();
    }


    private static string NormalizePath(string p) => Path.GetFullPath(p);

    private static string NormalizeDisplayPath(string p)
    {
        // Match perl's tendency to print relative-ish paths when invoked from cwd
        try
        {
            var cwd = Path.GetFullPath(Environment.CurrentDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var full = Path.GetFullPath(p);
            if (full.StartsWith(cwd + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return full.Substring(cwd.Length + 1);
            return p;
        }
        catch
        {
            return p;
        }
    }
}
