using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class SnefruTests
    {
        [Test]
        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new Snefru().ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return SnefruTestCases.All().Select(x => new object[] { x.Input, x.Snefru });
            }
        }
    }
}
