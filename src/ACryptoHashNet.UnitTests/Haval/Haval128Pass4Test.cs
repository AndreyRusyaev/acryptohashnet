using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval128Pass4Test : BaseHashTest
    {
        public Haval128Pass4Test() :
            base("haval[length=128, passes=4]",
                 new Haval128(HavalPassCount.Pass4)
             )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "ee6bbf4d6a46a679b3a856c88538bb98"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "5cd07f03330c3b5020b29ba75911e17d"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "958195d3dac591030eaa0292a37a0cf2"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "2215d3702a80025c858062c53d76cbe5"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "b2a73b99775ffb17cd8781b85ec66221"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "cad57c0563bda208d66bb89eb922e2a2"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "b163a0236635f8b2ffcf6e10c3ce2bb2"
                );
        }
    }
}
