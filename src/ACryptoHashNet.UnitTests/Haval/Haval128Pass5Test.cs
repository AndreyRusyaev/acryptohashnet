using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class Haval128Pass5Test : BaseHashTest
    {
        public Haval128Pass5Test() :
            base("haval[length=128, passes=5]",
                 new Haval128(HavalPassCount.Pass5)
             )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "184b8482a0c050dca54b59c7f05bf5dd"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "f23fbe704be8494bfa7a7fb4f8ab09e5"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "c97990f4fcc8fba76af935c405995355"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "466fdcd81c3477cac6a31ffa1c999ca8"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "0efff71d7d14344cba1f4b25f924a693"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "4b27d04ddb516bdcdfeb96eb8c7c8e90"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "e8271bfc50905f510b06690808abdb2b"
                );
        }
    }
}
