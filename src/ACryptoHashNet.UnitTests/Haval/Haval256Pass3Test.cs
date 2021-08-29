using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval256Pass3Test : BaseHashTest
    {
        public Haval256Pass3Test() :
            base("haval[length=256, passes=3]",
                new Haval256(HavalPassCount.Pass3)
            )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "47c838fbb4081d9525a0ff9b1e2c05a98f625714e72db289010374e27db021d8"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "91850c6487c9829e791fc5b58e98e372f3063256bb7d313a93f1f83b426aedcc"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "63238d99c02be18c3c5db7cce8432f51329012c228ccc17ef048a5d0fd22d4ae"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "72fad4bde1da8c8332fb60561a780e7f504f21547b98686824fc33fc796afa76"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "899397d96489281e9e76d5e65abab751f312e06c06c07c9c1d42abd31bb6a404"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "f92f518fe5b1e7e7d76e295dc3d0a9301da56e29374597eb6ff5a1f8c4fb9f93"
                );
        }
    }
}
