using System.Collections.Generic;
using System.Linq;

using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    internal class Sha2FamilyTests
    {
        [TestCaseSource(nameof(Sha2_224Cases))]
        public void SHA224(string input, string expected)
        {
            var actual = new SHA224().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha2_224Cases))]
        public void Sha2_224(string input, string expected)
        {
            var actual = new Sha2_224().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha2_256Cases))]
        public void SHA256(string input, string expected)
        {
            var actual = new SHA256().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha2_256Cases))]
        public void Sha2_256(string input, string expected)
        {
            var actual = new Sha2_256().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha2_384Cases))]
        public void SHA384(string input, string expected)
        {
            var actual = new SHA384().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha2_384Cases))]
        public void Sha2_384(string input, string expected)
        {
            var actual = new Sha2_384().ComputeHash(input.GetUtf8Bytes()).ToHexString(); ;
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha2_512Cases))]
        public void SHA512(string input, string expected)
        {
            var actual = new SHA512().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha2_512Cases))]
        public void Sha2_512(string input, string expected)
        {
            var actual = new Sha2_512().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }


        static IEnumerable<object[]> Sha2_224Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha2_224 });

        static IEnumerable<object[]> Sha2_256Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha2_256 });

        static IEnumerable<object[]> Sha2_384Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha2_384 });

        static IEnumerable<object[]> Sha2_512Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha2_512 });
    }
}
