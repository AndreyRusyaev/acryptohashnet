using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("MDTests")]
    public class MD5Test : BaseHashTest
    {
        public MD5Test() :
            base("md5", new MD5())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "d41d8cd98f00b204e9800998ecf8427e"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "0cc175b9c0f1b6a831c399e269772661"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #03",
                "abc",
                "900150983cd24fb0d6963f7d28e17f72"
                );
        }

        [Test]
        public void TestString_message_digest()
        {
            HashStringTest(
                "test #04",
                "message digest",
                "f96b697d7cb7938d525a2f31aaf161d0"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f"
                );
        }

        [Test]
        public void TestString_0_9_9()
        {
            HashStringTest(
                "test #07",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a"
                );
        }
    }
}
