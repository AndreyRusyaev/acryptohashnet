using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("MDTests")]
    public class MD2Test : BaseHashTest
    {
        public MD2Test() :
            base("md2", new MD2())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "8350e5a3e24c153df2275c9f80692773"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "32ec01ec4a6dac72c0ab96fb34c0b5d1"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #03",
                "abc",
                "da853b0d3f88d99b30283a69e6ded6bb"
                );
        }

        [Test]
        public void TestString_message_digest()
        {
            HashStringTest(
                "test #04",
                "message digest",
                "ab4f496bfb2a530b219ff33031fe06b0"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "4e8ddff3650292ab5a4108c3aa47940b"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "da33def2a42df13975352846c30338cd"
                );
        }

        [Test]
        public void TestString_0_9_9()
        {
            HashStringTest(
                "test #07",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "d5976f79d83d3a0dc9806c3c66f3efd8"
                );
        }
    }
}
