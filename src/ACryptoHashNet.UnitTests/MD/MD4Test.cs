using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("MDTests")]
    public class MD4Test : BaseHashTest
    {
        public MD4Test() :
            base("md4", new MD4())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "31d6cfe0d16ae931b73c59d7e0c089c0"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "bde52cb31de33e46245e05fbdbd6fb24"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #03",
                "abc",
                "a448017aaf21d8525fc10ae87aa6729d"
                );
        }

        [Test]
        public void TestString_message_digest()
        {
            HashStringTest(
                "test #04",
                "message digest",
                "d9130a8164549fe818874806e1c7014b"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4"
                );
        }

        [Test]
        public void TestString_0_9_9()
        {
            HashStringTest(
                "test #07",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536"
                );
        }
    }
}
