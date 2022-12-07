using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class MD4Tests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return MDFamilyTestCases.All().Select(x => new object[] { x.Input, x.Md4 });
            }
        }

        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new MD4().ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }        
    }
}
