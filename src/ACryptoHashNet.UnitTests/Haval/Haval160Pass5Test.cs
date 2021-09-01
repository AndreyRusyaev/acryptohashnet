using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval160Pass5Test : BaseHashTest
    {
        public Haval160Pass5Test() :
            base("haval[length=160, passes=5]",
                 new Haval160(HavalPassCount.Pass5)
             )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "255158cfc1eed1a7be7c55ddd64d9790415b933b"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "f5147df7abc5e3c81b031268927c2b5761b5a2b5"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "7730ca184cea2272e88571a7d533e035f33b1096"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "41cc7c1267e88cef0bb93697d0b6c8afe59061e6"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "917836a9d27eed42d406f6002e7d11a0f87c404c"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "6ddbde98ea1c4f8c7f360fb9163c7c952680aa70"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "494a002c5c2a4fd406097a55c078e0d1ef6815ce"
                );
        }
    }
}
