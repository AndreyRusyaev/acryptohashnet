using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("RIPEMDTests")]
    public class RIPEMD160Test : BaseHashTest
    {
        public RIPEMD160Test() :
            base("ripemd160", new RIPEMD160())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "9c1185a5c5e9fc54612808977ee8f548b2258d31"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #03",
                "abc",
                "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
                );
        }

        [Test]
        public void TestString_message_digest()
        {
            HashStringTest(
                "test #04",
                "message digest",
                "5d0689ef49d2fae572b881b123a85ffa21595f36"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "b0e20b6e3116640286ed3a87a5713079b21f5189"
                );
        }

        [Test]
        public void TestString_0_9_9()
        {
            HashStringTest(
                "test #07",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
                );
        }
    }
}
