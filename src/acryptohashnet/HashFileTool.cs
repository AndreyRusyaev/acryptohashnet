using System.IO;

using acryptohashnet;

// TODO: Generate for all supported hash algorithms
public static class HashFileTool
{
    public static HashResult Md2(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Md2(stream);
    }

    public static HashResult Md4(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Md4(stream);
    }

    public static HashResult Md5(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Md5(stream);
    }

    public static HashResult Sha1(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Sha1(stream);
    }

    public static HashResult Sha2_256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Sha2_256(stream);
    }

    public static HashResult Sha2_512(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Sha2_512(stream);
    }

    public static HashResult Sha3_256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Sha3_256(stream);
    }

    public static HashResult Sha3_512(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Sha3_512(stream);
    }

    public static HashResult Keccak256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Keccak256(stream);
    }

    public static HashResult Keccak512(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        return HashDataTool.Keccak512(stream);
    }
}