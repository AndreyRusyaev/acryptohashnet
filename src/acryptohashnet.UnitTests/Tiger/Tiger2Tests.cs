using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class Tiger2Tests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return TigerTestCases.All().Select(x => new object[] { x.Input, x.Tiger2 });
            }
        }

        [Test]
        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new Tiger2().ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }

        [Test]
        public void TestCase_1_million_times_a()
        {
            byte[] message = new byte[1_000_000];

            for (int ii = 0; ii < message.Length; ii++)
            {
                message[ii] = (byte)'a';
            }

            Assert.AreEqual(
                "e068281f060f551628cc5715b9d0226796914d45f7717cf4",
                new Tiger2().ComputeHash(message).ToHexString());
        }
    }
}
