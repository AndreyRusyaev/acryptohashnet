using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace acryptohashnet
{
    public static class ToDigestExtensions
    {
        public static string ToHexDigest(this Stream stream, HashAlgorithms hashAlgorithm)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            return stream.ToBytesDigest(hashAlgorithm).ToHex();
        }

        public static string ToHexDigest(this Stream stream, HashAlgorithm hashAlgorithm)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            return stream.ToBytesDigest(hashAlgorithm).ToHex();
        }

        public static byte[] ToBytesDigest(this Stream stream, HashAlgorithms hashAlgorithm)
        {
            return stream.ToBytesDigest(HashAlgorithmFactory.Create(hashAlgorithm));
        }

        public static byte[] ToBytesDigest(this Stream stream, HashAlgorithm hashAlgorithm)
        {
            return hashAlgorithm.ComputeHash(stream);
        }

        public static string ToHexDigest(this string message, HashAlgorithms hashAlgorithm)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return message.ToHexDigest(HashAlgorithmFactory.Create(hashAlgorithm));
        }
        public static string ToHexDigest(this string message, Encoding encoding, HashAlgorithms hashAlgorithm)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            if (encoding == null)
            {
                throw new ArgumentNullException(nameof(encoding));
            }

            return message.ToHexDigest(encoding, HashAlgorithmFactory.Create(hashAlgorithm));
        }

        public static string ToHexDigest(this string message, HashAlgorithm hashAlgorithm)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return message.ToBytesDigest(Encoding.UTF8, hashAlgorithm).ToHex();
        }
        public static string ToHexDigest(this string message, Encoding encoding, HashAlgorithm hashAlgorithm)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            if (encoding == null)
            {
                throw new ArgumentNullException(nameof(encoding));
            }

            return message.ToBytesDigest(encoding, hashAlgorithm).ToHex();
        }
        public static byte[] ToBytesDigest(this string message, Encoding encoding, HashAlgorithm hashAlgorithm)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return encoding.GetBytes(message).ToBytesDigest(hashAlgorithm);
        }

        public static byte[] ToBytesDigest(this byte[] message, HashAlgorithms hashAlgorithm)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return message.ToBytesDigest(HashAlgorithmFactory.Create(hashAlgorithm));
        }

        public static byte[] ToBytesDigest(this byte[] message, HashAlgorithm hashAlgorithm)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return hashAlgorithm.ComputeHash(message);
        }
        internal static string ToHex(this byte[] bytes)
        {
            return string.Join("", bytes.Select(x => x.ToString("x2")));
        }
    }
}
