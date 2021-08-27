using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval224Pass3Test : BaseHashTest
    {
        public Haval224Pass3Test() :
            base("haval[length=224, passes=3]",
                new Haval224(HavalPassCount.Pass3)
            )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "731814ba5605c59b673e4caae4ad28eeb515b3abc2b198336794e17b"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "ad33e0596c575d7175e9f72361ca767c89e46e2609d88e719ee69aaa"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "ee345c97a58190bf0f38bf7ce890231aa5fcf9862bf8e7bebbf76789"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "06ae38ebc43db58bd6b1d477c7b4e01b85a1e7b19b0bd088e33b58d1"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "939f7ed7801c1ce4b32bc74a4056eee6081c999ed246907adba880a7"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "3efaf428ccded50600039a5196c3e6ec88cf06bc5e55cb602cabfdac"
                );
        }
    }
}
