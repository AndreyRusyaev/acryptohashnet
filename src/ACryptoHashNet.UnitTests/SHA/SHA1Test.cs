using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("SHATests")]
    public class SHA1Test : BaseHashTest
    {
        public SHA1Test() :
            base("sha1", new SHA1())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #02",
                "abc",
                "a9993e364706816aba3e25717850c26c9cd0d89d"
                );
        }

        [Test]
        public void TestString_message_digest()
        {
            HashStringTest(
                "test #03",
                "message digest",
                "c12252ceda8be8994d5fa0290a47231c1d16aae3"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #04",
                "abcdefghijklmnopqrstuvwxyz",
                "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #05",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "761c457bf73b14d27e9e9265c46f4b4dda11f940"
                );
        }

        [Test]
        public void TestString_0_9_9()
        {
            HashStringTest(
                "test #06",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "50abf5706a150990a08b2c5ea40fa0e585554732"
                );
        }
    }
}
