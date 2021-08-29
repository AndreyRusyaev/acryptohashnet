using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("RIPEMDTests")]
    public class RIPEMD128Test : BaseHashTest
    {
        public RIPEMD128Test() :
            base("ripemd128", new RIPEMD128())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "cdf26213a150dc3ecb610f18f6b38b46"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "86be7afa339d0fc7cfc785e72f578d33"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #03",
                "abc",
                "c14a12199c66e4ba84636b0f69144c77"
                );
        }

        [Test]
        public void TestString_message_digest()
        {
            HashStringTest(
                "test #04",
                "message digest",
                "9e327b3d6e523062afc1132d7df9d1b8"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "fd2aa607f71dc8f510714922b371834e"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d1e959eb179c911faea4624c60c5c702"
                );
        }

        [Test]
        public void TestString_0_9_9()
        {
            HashStringTest(
                "test #07",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "3f45ef194732c2dbb2c4a2c769795fa3"
                );
        }
    }
}
