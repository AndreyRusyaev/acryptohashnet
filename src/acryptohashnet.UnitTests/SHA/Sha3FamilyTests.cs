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
            var actual = input.ToHexDigest(new Sha3_224());
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha3_256Cases))]
        public void Sha3_256(string input, string expected)
        {
            var actual = input.ToHexDigest(new Sha3_256());
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha3_384Cases))]
        public void Sha3_384(string input, string expected)
        {
            var actual = input.ToHexDigest(new Sha3_384());
            Assert.That(actual, Is.EqualTo(expected));
        }

        [TestCaseSource(nameof(Sha3_512Cases))]
        public void Sha3_512(string input, string expected)
        {
            var actual = input.ToHexDigest(new Sha3_512());
            Assert.That(actual, Is.EqualTo(expected));
        }


        static IEnumerable<object[]> Sha3_224Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha3_224 });

        static IEnumerable<object[]> Sha3_256Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha3_256 });

        static IEnumerable<object[]> Sha3_384Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha3_384 });

        static IEnumerable<object[]> Sha3_512Cases = SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha3_512 });
    }
}
