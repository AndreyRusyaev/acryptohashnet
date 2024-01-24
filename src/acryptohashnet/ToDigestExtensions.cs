using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace acryptohashnet
{
    public static class ToDigestExtensions
    {
        public static string ToHexDigest(this string message, HashAlgorithms hashAlgorithm)
        {
            return message.ToHexDigest(HashAlgorithmFactory.Create(hashAlgorithm));
        }
        public static string ToHexDigest(this string message, Encoding encoding, HashAlgorithms hashAlgorithm)
        {
            return message.ToHexDigest(encoding, HashAlgorithmFactory.Create(hashAlgorithm));
        }

        public static string ToHexDigest(this string message, HashAlgorithm hashAlgorithm)
        {
            return message.ToBytesDigest(Encoding.UTF8, hashAlgorithm).ToHex();
        }
        public static string ToHexDigest(this string message, Encoding encoding, HashAlgorithm hashAlgorithm)
        {
            return message.ToBytesDigest(encoding, hashAlgorithm).ToHex();
        }

        public static byte[] ToBytesDigest(this string message, Encoding encoding, HashAlgorithm hashAlgorithm)
        {
            return encoding.GetBytes(message).ToBytesDigest(hashAlgorithm);
        }

        public static byte[] ToBytesDigest(this byte[] message, HashAlgorithms hashAlgorithm)
        {
            return message.ToBytesDigest(HashAlgorithmFactory.Create(hashAlgorithm));
        }

        public static byte[] ToBytesDigest(this byte[] message, HashAlgorithm hashAlgorithm)
        {
            return hashAlgorithm.ComputeHash(message);
        }
        internal static string ToHex(this byte[] bytes)
        {
            return string.Join("", bytes.Select(x => x.ToString("x2")));
        }
    }
}
