using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class SHA384Tests
    {
        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new SHA384().ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [Test]
        public void Sha2_384_ValidateWithSystemCryptography()
        {
            var systemImpl = System.Security.Cryptography.SHA384.Create();
            var acryptohashnetImpl = new SHA384();

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
                return SHAFamilyTestCases.All().Select(x => new object[] { x.Input, x.Sha384 });
            }
        }
    }
}
