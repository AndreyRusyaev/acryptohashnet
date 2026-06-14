using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace acryptohashnet;

// TODO: Generate for all supported hash algorithms
public static class HashDataTool
{
    private static readonly Lazy<MD2> md2 = new();

    private static readonly Lazy<MD4> md4 = new();

    private static readonly Lazy<MD5> md5 = new();

    private static readonly Lazy<SHA1> sha1_256 = new();

    private static readonly Lazy<Sha2_256> sha2_256 = new();

    private static readonly Lazy<Sha2_512> sha2_512 = new();

    private static readonly Lazy<Sha3_256> sha3_256 = new();

    private static readonly Lazy<Sha3_512> sha3_512 = new();

    private static readonly Lazy<Keccak256> keccak256 = new();

    private static readonly Lazy<Keccak512> keccak512 = new();

    public static HashResult Md2(byte[] input)
    {
        return HashData(input, md2.Value);
    }

    public static HashResult Md2(string input)
    {
        return HashData(input, md2.Value);
    }

    public static HashResult Md2(Stream input)
    {
        return HashData(input, md2.Value);
    }

    public static HashResult Md4(byte[] input)
    {
        return HashData(input, md4.Value);
    }

    public static HashResult Md4(string input)
    {
        return HashData(input, md4.Value);
    }

    public static HashResult Md4(Stream input)
    {
        return HashData(input, md5.Value);
    }

    public static HashResult Md5(byte[] input)
    {
        return HashData(input, md5.Value);
    }

    public static HashResult Md5(Stream input)
    {
        return HashData(input, md5.Value);
    }

    public static HashResult Md5(string input)
    {
        return HashData(input, md5.Value);
    }

    public static HashResult Sha1(byte[] input)
    {
        return HashData(input, sha1_256.Value);
    }

    public static HashResult Sha1(string input)
    {
        return HashData(input, sha1_256.Value);
    }

    public static HashResult Sha1(Stream input)
    {
        return HashData(input, sha1_256.Value);
    }

    public static HashResult Sha2_256(byte[] input)
    {
        return HashData(input, sha2_256.Value);
    }

    public static HashResult Sha2_256(string input)
    {
        return HashData(input, sha2_256.Value);
    }

    public static HashResult Sha2_256(Stream input)
    {
        return HashData(input, sha2_256.Value);
    }

    public static HashResult Sha2_512(byte[] input)
    {
        return HashData(input, sha2_512.Value);
    }

    public static HashResult Sha2_512(string input)
    {
        return HashData(input, sha2_512.Value);
    }

    public static HashResult Sha2_512(Stream input)
    {
        return HashData(input, sha2_512.Value);
    }

    public static HashResult Sha3_256(byte[] input)
    {
        return HashData(input, sha3_256.Value);
    }

    public static HashResult Sha3_256(string input)
    {
        return HashData(input, sha3_256.Value);
    }

    public static HashResult Sha3_256(Stream input)
    {
        return HashData(input, sha3_256.Value);
    }

    public static HashResult Sha3_512(byte[] input)
    {
        return HashData(input, sha3_512.Value);
    }

    public static HashResult Sha3_512(string input)
    {
        return HashData(input, sha3_512.Value);
    }

    public static HashResult Sha3_512(Stream input)
    {
        return HashData(input, sha3_512.Value);
    }

    public static HashResult Keccak256(byte[] input)
    {
        return HashData(input, keccak256.Value);
    }

    public static HashResult Keccak256(string input)
    {
        return HashData(input, keccak256.Value);
    }

    public static HashResult Keccak256(Stream input)
    {
        return HashData(input, keccak256.Value);
    }

    public static HashResult Keccak512(string input)
    {
        return HashData(input, keccak512.Value);
    }

    public static HashResult Keccak512(Stream input)
    {
        return HashData(input, keccak512.Value);
    }

    internal static HashResult HashData(byte[] input, HashAlgorithm hashAlgorithm)
    {
        return new HashResult(hashAlgorithm.ComputeHash(input));
    }

    internal static HashResult HashData(string input, HashAlgorithm hashAlgorithm)
    {
        return HashData(input, Encoding.UTF8, hashAlgorithm);
    }

    internal static HashResult HashData(string input, Encoding encoding, HashAlgorithm hashAlgorithm)
    {
        return HashData(encoding.GetBytes(input), hashAlgorithm);
    }

    internal static HashResult HashData(Stream input, HashAlgorithm hashAlgorithm)
    {
        return new HashResult(hashAlgorithm.ComputeHash(input));
    }

    #if NET6_0_OR_GREATER

    internal static async Task<HashResult> HashDataAsync(Stream input, HashAlgorithm hashAlgorithm, CancellationToken cancellationToken = default)
    {
        return new HashResult(await hashAlgorithm.ComputeHashAsync(input, cancellationToken).ConfigureAwait(false));
    }

    #endif
}