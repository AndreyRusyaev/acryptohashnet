using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class RIPEMD160Tests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return RIPEMDFamilyTestCases.All().Select(x => new object[] { x.Input, x.RipeMd160 });
            }
        }

        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new RIPEMD160().ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }
    }
}
