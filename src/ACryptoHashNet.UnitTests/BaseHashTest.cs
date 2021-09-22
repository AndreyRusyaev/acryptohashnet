using System;
using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    public abstract class BaseHashTest
    {
        public BaseHashTest(string hashName, HashAlgorithm algorithm)
        {
            AlgorithmName = hashName;
            Algorithm = algorithm;
        }

        public string AlgorithmName { get; }

        public HashAlgorithm Algorithm { get; }

        [Test]
        public void HashAlgorithmCanBeReused()
        {
            var input = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");

            var hash1 = Algorithm.ComputeHash(input);
            var hash2 = Algorithm.ComputeHash(input);

            CollectionAssert.AreEqual(hash1, hash2);
        }

        [Test]
        public void TransformByTwoBlocksShouldHaveSameResult()
        {
            var expected =
                Algorithm.ComputeHash(Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz"));

            byte[] b1 = Encoding.UTF8.GetBytes("abcdefghijklm");
            byte[] b2 = Encoding.UTF8.GetBytes("nopqrstuvwxyz");

            Algorithm.Initialize();
            Algorithm.TransformBlock(b1, 0, b1.Length, null, 0);
            Algorithm.TransformFinalBlock(b2, 0, b2.Length);

            CollectionAssert.AreEqual(expected, Algorithm.Hash);
        }

        [Test]
        public void TransformByTwoBlocksAndEmptyFinalBlockShouldHaveSameResult()
        {
            var expected =
                Algorithm.ComputeHash(Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz"));

            byte[] b1 = Encoding.UTF8.GetBytes("abcdefghijklm");
            byte[] b2 = Encoding.UTF8.GetBytes("nopqrstuvwxyz");

            Algorithm.Initialize();
            Algorithm.TransformBlock(b1, 0, b1.Length, null, 0);
            Algorithm.TransformBlock(b2, 0, b2.Length, null, 0);
            Algorithm.TransformFinalBlock(new byte[0], 0, 0);

            CollectionAssert.AreEqual(expected, Algorithm.Hash);
        }

        [Test]
        public void TransformByBytesShouldHaveSameResult()
        {
            var binaryMessage = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expected = Algorithm.ComputeHash(binaryMessage);

            Algorithm.Initialize();

            for (int ii = 0; ii < binaryMessage.Length; ii++)
            {
                Algorithm.TransformBlock(binaryMessage, ii, 1, null, 0);
            }

            Algorithm.TransformFinalBlock(new byte[0], 0, 0);

            CollectionAssert.AreEqual(expected, Algorithm.Hash);
        }

        [Test]
        public void TransformOnlyFinalBlockShouldHaveSameResult()
        {
            var binaryMessage = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expected = Algorithm.ComputeHash(binaryMessage);

            Algorithm.Initialize();
            Algorithm.TransformFinalBlock(binaryMessage, 0, binaryMessage.Length);

            CollectionAssert.AreEqual(expected, Algorithm.Hash);
        }


        [Test]
        public void TransformEmptyFinalBlockShouldHaveSameResult()
        {
            var binaryMessage = Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz");
            var expected = Algorithm.ComputeHash(binaryMessage);

            Algorithm.Initialize();
            Algorithm.TransformBlock(binaryMessage, 0, binaryMessage.Length, null, 0);
            Algorithm.TransformFinalBlock(new byte[0], 0, 0);

            CollectionAssert.AreEqual(expected, Algorithm.Hash);
        }

        protected string HashString(string input)
        {
            return HashString(input, Encoding.UTF8);
        }

        protected string HashString(string input, Encoding encoding)
        {
            var result = Algorithm.ComputeHash(encoding.GetBytes(input));

            return StringUtils.ByteArrayToHexString(result);
        }

        protected void HashStringTest(string testInfo, string source, string expected)
        {
            StringAssert.AreEqualIgnoringCase(
                expected,
                HashString(source),
                string.Format("{1}: {0} hash of string = '{2}' is wrong!", this.AlgorithmName, testInfo, source));
        }
    }
}
