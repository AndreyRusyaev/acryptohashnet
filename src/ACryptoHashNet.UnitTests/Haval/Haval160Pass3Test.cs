using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval160Pass3Test : BaseHashTest
    {
        public Haval160Pass3Test() :
            base("haval[length=160, passes=3]",
                 new Haval160(HavalPassCount.Pass3)
             )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "d353c3ae22a25401d257643836d7231a9a95f953"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "4da08f514a7275dbc4cece4a347385983983a830"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "8822bc6f3e694e73798920c77ce3245120dd8214"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "be68981eb3ebd3f6748b081ee5d4e1818f9ba86c"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "eba9fa6050f24c07c29d1834a60900ea4e32e61b"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "97dc988d97caae757be7523c4e8d4ea63007a4b9"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "3fadf42851f001aae23cc966611625a83bda8a29"
                );
        }
    }
}
