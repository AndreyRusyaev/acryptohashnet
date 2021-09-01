using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval192Pass4Test
        : BaseHashTest
    {
        public Haval192Pass4Test() :
            base("haval[length=192, passes=4]",
                new Haval192(HavalPassCount.Pass4)
            )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "4a8372945afa55c7dead800311272523ca19d42ea47b72da"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "856c19f86214ea9a8a2f0c4b758b973cce72a2d8ff55505c"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "0c1396d7772689c46773f3daaca4efa982adbfb2f1467eea"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "c3a5420bb9d7d82a168f6624e954aaa9cdc69fb0f67d785e"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "2e2e581d725e799fda1948c75e85a28cfe1cf0c6324a1ada"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "e5c9f81ae0b31fc8780fc37cb63bb4ec96496f79a9b58344"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "d1f8b6e0f8e939f21013b9bca5b25d8067974aa254ec71cf"
                );
        }
    }
}
