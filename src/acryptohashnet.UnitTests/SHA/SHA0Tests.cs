using System.Collections.Generic;
using System.Linq;

using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class SHA0Tests
    {
        [TestCaseSource(nameof(Sha0TestCases))]
        public void Sha0(string input, string expected)
        {
            var actual = input.ToHexDigest(new SHA0());
            Assert.That(actual, Is.EqualTo(expected));
        }

        public static IEnumerable<object[]> Sha0TestCases
        {
            get
            {
                return SHAFamilyTestCases.All().Select(x => new object[] { x.Message, x.Sha0 });
            }
        }
    }
}
