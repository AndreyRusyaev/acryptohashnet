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
            var actual = input.ToHexDigest(new SHA1());
            Assert.That(actual, Is.EqualTo(expected));
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
