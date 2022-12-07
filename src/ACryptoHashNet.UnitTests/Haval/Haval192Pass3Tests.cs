using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class Haval192Pass3Tests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return HavalTestCases.All().Select(x => new object[] { x.Input, x.Haval192Pass3 });
            }
        }

        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new Haval192(HavalPassCount.Pass3).ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }
    }
}
