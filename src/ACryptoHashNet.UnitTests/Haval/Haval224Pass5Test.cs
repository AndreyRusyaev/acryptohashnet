using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval224Pass5Test : BaseHashTest
    {
        public Haval224Pass5Test() :
            base("haval[length=224, passes=5]",
                new Haval224(HavalPassCount.Pass5)
            )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "67b3cb8d4068e3641fa4f156e03b52978b421947328bfb9168c7655d"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "9d7ae77b8c5c8c1c0ba854ebe3b2673c4163cfd304ad7cd527ce0c82"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "59836d19269135bc815f37b2aeb15f894b5435f2c698d57716760f2b"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "1b360acff7806502b5d40c71d237cc0c40343d2000ae2f65cf487c94"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "180aed7f988266016719f60148ba2c9b4f5ec3b9758960fc735df274"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "36a5bcf298afe7f6796284b29c591896d54b4e982ed2c847c9857ccf"
                );
        }
    }
}
