using System.Collections.Generic;
using System.Linq;

using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class SHA1Tests
    {
        [TestCaseSource(nameof(Sha1TestCases))]
        public void Sha1(string input, string expected)
        {
            var actual = new SHA1().ComputeHash(input.GetUtf8Bytes()).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [Test]
        public void ValidateWithSystemCryptography()
        {
            var systemImpl = System.Security.Cryptography.SHA1.Create();
            var acryptohashnetImpl = new SHA1();

            for (var ii = 0; ii < 1024; ii += 1)
            {
                var input = new string('a', ii);

                var expected = systemImpl.ComputeHash(input.GetUtf8Bytes()).ToHexString();
                var actual = acryptohashnetImpl.ComputeHash(input.GetUtf8Bytes()).ToHexString();

                Assert.That(actual, Is.EqualTo(expected));
            }
        }

        public static IEnumerable<object[]> Sha1TestCases
        {
            get
            {
                return SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha1 });
            }
        }
    }
}
