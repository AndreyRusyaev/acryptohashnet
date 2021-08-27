using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("SHATests")]
    public class SHA0Test : BaseHashTest
    {
        public SHA0Test() :
            base("sha0", new SHA0())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "f96cea198ad1dd5617ac084a3d92c6107708c0ef"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #02",
                "abc",
                "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"
                );
        }

        [Test]
        public void TestString_message_digest()
        {
            HashStringTest(
                "test #03",
                "message digest",
                "c1b0f222d150ebb9aa36a40cafdc8bcbed830b14"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #04",
                "abcdefghijklmnopqrstuvwxyz",
                "b40ce07a430cfd3c033039b9fe9afec95dc1bdcd"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #05",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "79e966f7a3a990df33e40e3d7f8f18d2caebadfa"
                );
        }

        [Test]
        public void TestString_0_9_9()
        {
            HashStringTest(
                "test #06",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "4aa29d14d171522ece47bee8957e35a41f3e9cff"
                );
        }
    }
}
