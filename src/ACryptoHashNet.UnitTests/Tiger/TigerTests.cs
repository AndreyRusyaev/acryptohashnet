using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class TigerTests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return TigerTestCases.All().Select(x => new object[] { x.Input, x.Tiger });
            }
        }

        [Test]
        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new Tiger().ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
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
                "6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41",
                new Tiger().ComputeHash(message).ToHexString());
        }

        [Test]
        public void TestString_64Kb()
        {
            byte[] message = new byte[65536];

            for (int ii = 0; ii < message.Length; ii++)
            {
                message[ii] = (byte)(ii & 0xff);
            }

            Assert.AreEqual(
                "fdf4f5b35139f48e710e421be5af411de1a8aac333f26204",
                 new Tiger().ComputeHash(message).ToHexString());
        }
    }
}
