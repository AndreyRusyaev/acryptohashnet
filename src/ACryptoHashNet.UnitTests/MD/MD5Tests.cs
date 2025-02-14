using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class MD5Tests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return MDFamilyTestCases.All().Select(x => new object[] { x.Input, x.Md5 });
            }
        }

        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new MD5().ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [Test]
        public void ValidateWithSystemCryptography()
        {
            var systemImpl = System.Security.Cryptography.MD5.Create();
            var acryptohashnetImpl = new MD5();

            for (var ii = 0; ii < 1024; ii += 1)
            {
                var input = new string('a', ii);

                var expected = systemImpl.ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
                var actual = acryptohashnetImpl.ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();

                Assert.That(actual, Is.EqualTo(expected));
            }
        }
    }
}
