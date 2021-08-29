using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval256Pass4Test : BaseHashTest
    {
        public Haval256Pass4Test() :
            base("haval[length=256, passes=4]",
                new Haval256(HavalPassCount.Pass4)
            )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "e686d2394a49b44d306ece295cf9021553221db132b36cc0ff5b593d39295899"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "e20643cfa66f5be2145d13ed09c2ff622b3f0da426a693fa3b3e529ca89e0d3c"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "ace5d6e5b155f7c9159f6280327b07cbd4ff54143dc333f0582e9bceb895c05d"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "124f6eb645dc407637f8f719cc31250089c89903bf1db8fac21ea4614df4e99a"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "46a3a1dfe867ede652425ccd7fe8006537ead26372251686bea286da152dc35a"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "68ffd0fbc2e2973b4baae73a418029fec08c050b4cf9352c29411510f730cd08"
                );
        }
    }
}
