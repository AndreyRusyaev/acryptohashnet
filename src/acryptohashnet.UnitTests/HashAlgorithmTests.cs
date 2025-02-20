﻿using NUnit.Framework;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace acryptohashnet.UnitTests
{
    internal class HashAlgorithmTests
    {
        public static IEnumerable<HashAlgorithm> HashAlgorithms
        {
            get
            {
                return new HashAlgorithm[]
                {
                    new Haval128(HavalPassCount.Pass3),
                    new Haval128(HavalPassCount.Pass4),
                    new Haval128(HavalPassCount.Pass5),
                    new Haval160(HavalPassCount.Pass3),
                    new Haval160(HavalPassCount.Pass4),
                    new Haval160(HavalPassCount.Pass5),
                    new Haval192(HavalPassCount.Pass3),
                    new Haval192(HavalPassCount.Pass4),
                    new Haval192(HavalPassCount.Pass5),
                    new Haval224(HavalPassCount.Pass3),
                    new Haval224(HavalPassCount.Pass4),
                    new Haval224(HavalPassCount.Pass5),
                    new Haval256(HavalPassCount.Pass3),
                    new Haval256(HavalPassCount.Pass4),
                    new Haval256(HavalPassCount.Pass5),

                    new MD2(),
                    new MD4(),
                    new MD5(),

                    new RIPEMD128(),
                    new RIPEMD160(),

                    new SHA0(),
                    new SHA1(),

                    new Sha2_224(),
                    new Sha2_256(),
                    new Sha2_384(),
                    new Sha2_512(),

                    new Sha3_224(),
                    new Sha3_256(),
                    new Sha3_384(),
                    new Sha3_512(),

                    new Snefru(),
                    new Snefru256(),

                    new Tiger(),
                    new Tiger2()
                };
            }
        }

        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void HashAlgorithmCanBeReused(HashAlgorithm hashAlgorithm)
        {
            var input = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");

            var hash1 = hashAlgorithm.ComputeHash(input);
            var hash2 = hashAlgorithm.ComputeHash(input);

            Assert.That(hash1.ToHexString(), Is.EqualTo(hash2.ToHexString()));
        }

        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void TransformByTwoBlocksShouldHaveSameResult(HashAlgorithm hashAlgorithm)
        {
            var binaryMessage = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expected =
                hashAlgorithm.ComputeHash(binaryMessage).ToHexString();

            byte[] b1 = Encoding.UTF8.GetBytes("abcdefghijklm");
            byte[] b2 = Encoding.UTF8.GetBytes("nopqrstuvwxyz");

            hashAlgorithm.Initialize();
            hashAlgorithm.TransformBlock(b1, 0, b1.Length, null, 0);
            hashAlgorithm.TransformFinalBlock(b2, 0, b2.Length);

            Assert.That(
                hashAlgorithm.Hash?.ToHexString(),
                Is.EqualTo(expected));
        }

        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void TransformByTwoBlocksAndEmptyFinalBlockShouldHaveSameResult(HashAlgorithm hashAlgorithm)
        {
            var binaryMessage = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expected =
                hashAlgorithm.ComputeHash(binaryMessage).ToHexString();

            byte[] b1 = Encoding.UTF8.GetBytes("abcdefghijklm");
            byte[] b2 = Encoding.UTF8.GetBytes("nopqrstuvwxyz");

            hashAlgorithm.Initialize();
            hashAlgorithm.TransformBlock(b1, 0, b1.Length, null, 0);
            hashAlgorithm.TransformBlock(b2, 0, b2.Length, null, 0);
            hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);

            Assert.That(
                hashAlgorithm.Hash?.ToHexString(),
                Is.EqualTo(expected));
        }

        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void TransformByBytesShouldHaveSameResult(HashAlgorithm hashAlgorithm)
        {
            var binaryMessage = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expected = hashAlgorithm.ComputeHash(binaryMessage).ToHexString();

            hashAlgorithm.Initialize();

            for (int ii = 0; ii < binaryMessage.Length; ii++)
            {
                hashAlgorithm.TransformBlock(binaryMessage, ii, 1, null, 0);
            }

            hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);

            Assert.That(
                hashAlgorithm.Hash?.ToHexString(),
                Is.EqualTo(expected));
        }

        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void TransformOnlyFinalBlockShouldHaveSameResult(HashAlgorithm hashAlgorithm)
        {
            var binaryMessage = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expected = hashAlgorithm.ComputeHash(binaryMessage).ToHexString();

            hashAlgorithm.Initialize();
            hashAlgorithm.TransformFinalBlock(binaryMessage, 0, binaryMessage.Length);

            Assert.That(
                hashAlgorithm.Hash?.ToHexString(),
                Is.EqualTo(expected));
        }


        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void TransformEmptyFinalBlockShouldHaveSameResult(HashAlgorithm hashAlgorithm)
        {
            var binaryMessage = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expected = hashAlgorithm.ComputeHash(binaryMessage).ToHexString();

            hashAlgorithm.Initialize();
            hashAlgorithm.TransformBlock(binaryMessage, 0, binaryMessage.Length, null, 0);
            hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);

            Assert.That(
                hashAlgorithm.Hash?.ToHexString(),
                Is.EqualTo(expected));
        }

        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void TransformByBlockSizeOffByOneMinusBlockShouldHaveSameResult(HashAlgorithm hashAlgorithm)
        {
            string message = GenerateMessageWithAtLeastBlocks(hashAlgorithm, 3);

            var binaryMessage = Encoding.UTF8.GetBytes(message);
            var expected = hashAlgorithm.ComputeHash(binaryMessage).ToHexString();

            hashAlgorithm.Initialize();
            var blockSize = hashAlgorithm.HashSize / 8 - 1;
            var remainingBytes = binaryMessage.Length % blockSize;
            for (int ii = 0; ii < binaryMessage.Length - remainingBytes; ii += blockSize)
            {
                hashAlgorithm.TransformBlock(binaryMessage, ii, blockSize, null, 0);
            }
            hashAlgorithm.TransformFinalBlock(binaryMessage, binaryMessage.Length - remainingBytes, remainingBytes);

            Assert.That(
                hashAlgorithm.Hash?.ToHexString(),
                Is.EqualTo(expected));
        }

        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void TransformByExactlyByBlockSizeBlockShouldHaveSameResult(HashAlgorithm hashAlgorithm)
        {
            string message = GenerateMessageWithAtLeastBlocks(hashAlgorithm, 3);

            var binaryMessage = Encoding.UTF8.GetBytes(message);
            var expected = hashAlgorithm.ComputeHash(binaryMessage).ToHexString();

            hashAlgorithm.Initialize();
            var blockSize = hashAlgorithm.HashSize / 8;
            var remainingBytes = binaryMessage.Length % blockSize;
            for (int ii = 0; ii < binaryMessage.Length - remainingBytes; ii += blockSize)
            {
                hashAlgorithm.TransformBlock(binaryMessage, ii, blockSize, null, 0);
            }
            hashAlgorithm.TransformFinalBlock(binaryMessage, binaryMessage.Length - remainingBytes, remainingBytes);

            Assert.That(
                hashAlgorithm.Hash?.ToHexString(),
                Is.EqualTo(expected));
        }

        [Test]
        [TestCaseSource(nameof(HashAlgorithms))]
        public void TransformByBlockSizeOffByOnePlusBlockShouldHaveSameResult(HashAlgorithm hashAlgorithm)
        {
            string message = GenerateMessageWithAtLeastBlocks(hashAlgorithm, 3);

            var binaryMessage = Encoding.UTF8.GetBytes(message);
            var expected = hashAlgorithm.ComputeHash(binaryMessage).ToHexString();

            hashAlgorithm.Initialize();
            var blockSize = hashAlgorithm.HashSize / 8 + 1;
            var remainingBytes = binaryMessage.Length % blockSize;
            for (int ii = 0; ii < binaryMessage.Length - remainingBytes; ii += blockSize)
            {
                hashAlgorithm.TransformBlock(binaryMessage, ii, blockSize, null, 0);
            }
            hashAlgorithm.TransformFinalBlock(binaryMessage, binaryMessage.Length - remainingBytes, remainingBytes);

            Assert.That(
                hashAlgorithm.Hash?.ToHexString(),
                Is.EqualTo(expected));
        }

        private static string GenerateMessageWithAtLeastBlocks(HashAlgorithm hashAlgorithm, int minimumBlocksRequired)
        {
            StringBuilder builder = new StringBuilder();
            while (true)
            {
                builder.Append("abcdefghijklmnopqrstuvwxyz");

                var messageBlocks = (builder.Length << 3) / hashAlgorithm.HashSize;
                if (messageBlocks > minimumBlocksRequired)
                {
                    break;
                }
            }

            return builder.ToString();
        }
    }
}
