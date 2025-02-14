using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class SHA1Tests
    {
        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new SHA1().ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
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

                var expected = systemImpl.ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
                var actual = acryptohashnetImpl.ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();

                Assert.That(actual, Is.EqualTo(expected));
            }
        }

        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return SHAFamilyTestCases.All().Select(x => new object[] { x.Input, x.Sha1 });
            }
        }
    }
}
