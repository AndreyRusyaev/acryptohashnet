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

        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return SHAFamilyTestCases.All().Select(x => new object[] { x.Input, x.Sha1 });
            }
        }
    }
}
