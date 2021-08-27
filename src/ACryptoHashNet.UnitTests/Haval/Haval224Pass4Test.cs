using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval224Pass4Test : BaseHashTest
    {
        public Haval224Pass4Test() :
            base("haval[length=224, passes=4]",
                new Haval224(HavalPassCount.Pass4)
            )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "742f1dbeeaf17f74960558b44f08aa98bdc7d967e6c0ab8f799b3ac1"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "85538ffc06f3b1c693c792c49175639666f1dde227da8bd000c1e6b4"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "bebd7816f09baeecf8903b1b9bc672d9fa428e462ba699f814841529"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "a0ac696cdb2030fa67f6cc1d14613b1962a7b69b4378a9a1b9738796"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "3e63c95727e0cd85d42034191314401e42ab9063a94772647e3e8e0f"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "0f0120310e2dd9972e2e1619a96cc20478271d090b6c21e7eb33eb0c"
                );
        }
    }
}
