using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class KeccakTests
    {
        [TestCaseSource(nameof(Keccak224_TestCases))]
        public void Keccak224(string input, string expected)
        {
            var actual = new Keccak224().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Keccak256_TestCases))]
        public void Keccak256(string input, string expected)
        {
            var actual = new Keccak256().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Keccak384_TestCases))]
        public void Keccak384(string input, string expected)
        {
            var actual = new Keccak384().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Keccak512_TestCases))]
        public void Keccak512(string input, string expected)
        {
            var actual = new Keccak512().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        public static IEnumerable<object[]> Keccak224_TestCases => KeccakTestCases.All().Select(x => new object[] { x.Message, x.Keccak224 });

        public static IEnumerable<object[]> Keccak256_TestCases => KeccakTestCases.All().Select(x => new object[] { x.Message, x.Keccak256 });

        public static IEnumerable<object[]> Keccak384_TestCases => KeccakTestCases.All().Select(x => new object[] { x.Message, x.Keccak384 });

        public static IEnumerable<object[]> Keccak512_TestCases => KeccakTestCases.All().Select(x => new object[] { x.Message, x.Keccak512 });
    }
}
