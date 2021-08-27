using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval128Pass3Test : BaseHashTest
    {
        public Haval128Pass3Test() :
            base("haval[length=128, passes=3]",
                 new Haval128(HavalPassCount.Pass3)
             )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "c68f39913f901f3ddf44c707357a7d70"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "0cd40739683e15f01ca5dbceef4059f1"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "dc1f3c893d17cc4edd9ae94af76a0af0"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "d4be2164ef387d9f4d46ea8efb180cf5"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "dc502247fb3eb8376109eda32d361d82"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "de5eb3f7d9eb08fae7a07d68e3047ec6"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "7a4272c08c8439de627fd5f5fee6ca16"
                );
        }
    }
}
