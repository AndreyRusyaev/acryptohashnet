using NUnit.Framework;

using System.Collections.Generic;
using System.Linq;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class Sha3FamilyTests
    {
        [TestCaseSource(nameof(Sha3_224Cases))]
        public void Sha3_224(string input, string expected)
        {
            var actual = new Sha3_224().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha3_256Cases))]
        public void Sha3_256(string input, string expected)
        {
            var actual = new Sha3_256().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha3_384Cases))]
        public void Sha3_384(string input, string expected)
        {
            var actual = new Sha3_384().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha3_512Cases))]
        public void Sha3_512(string input, string expected)
        {
            var actual = new Sha3_512().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [Test]
        public void Sha3_256_ValidateWithSystemCryptography()
        {
            var systemImpl = System.Security.Cryptography.SHA3_256.Create();
            var acryptohashnetImpl = new Sha3_256();

            for (var ii = 0; ii < 1024; ii += 1)
            {
                var input = new string('a', ii);

                var expected = systemImpl.ComputeHash(input.GetUtf8Bytes()).ToHexString();
                var actual = acryptohashnetImpl.ComputeHash(input.GetUtf8Bytes()).ToHexString();

                Assert.That(actual, Is.EqualTo(expected));
            }
        }

        [Test]
        public void Sha3_384_ValidateWithSystemCryptography()
        {
            var systemImpl = System.Security.Cryptography.SHA3_384.Create();
            var acryptohashnetImpl = new Sha3_384();

            for (var ii = 0; ii < 1024; ii += 1)
            {
                var input = new string('a', ii);

                var expected = systemImpl.ComputeHash(input.GetUtf8Bytes()).ToHexString();
                var actual = acryptohashnetImpl.ComputeHash(input.GetUtf8Bytes()).ToHexString();

                Assert.That(actual, Is.EqualTo(expected));
            }
        }

        [Test]
        public void Sha3_512_ValidateWithSystemCryptography()
        {
            var systemImpl = System.Security.Cryptography.SHA3_512.Create();
            var acryptohashnetImpl = new Sha3_512();

            for (var ii = 0; ii < 1024; ii += 1)
            {
                var input = new string('a', ii);

                var expected = systemImpl.ComputeHash(input.GetUtf8Bytes()).ToHexString();
                var actual = acryptohashnetImpl.ComputeHash(input.GetUtf8Bytes()).ToHexString();

                Assert.That(actual, Is.EqualTo(expected));
            }
        }

        static IEnumerable<object[]> Sha3_224Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha3_224 });

        static IEnumerable<object[]> Sha3_256Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha3_256 });

        static IEnumerable<object[]> Sha3_384Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha3_384 });

        static IEnumerable<object[]> Sha3_512Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha3_512 });
    }
}
