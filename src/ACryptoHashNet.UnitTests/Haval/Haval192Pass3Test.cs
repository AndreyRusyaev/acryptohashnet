using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("HavalTests")]
    public class Haval192Pass3Test : BaseHashTest
    {
        public Haval192Pass3Test() :
            base("haval[length=192, passes=3]",
                 new Haval192(HavalPassCount.Pass3)
             )
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "b359c8835647f5697472431c142731ff6e2cddcacc4f6e08"
                );
        }

        [Test]
        public void TestString_HAVAL()
        {
            HashStringTest(
                "test #03",
                "HAVAL",
                "8da26ddab4317b392b22b638998fe65b0fbe4610d345cf89"
                );
        }

        [Test]
        public void TestString_0_9()
        {
            HashStringTest(
                "test #04",
                "0123456789",
                "de561f6d818a760d65bdd2823abe79cdd97e6cfa4021b0c8"
                );
        }

        [Test]
        public void TestString_a2z()
        {
            HashStringTest(
                "test #05",
                "abcdefghijklmnopqrstuvwxyz",
                "a25e1456e6863e7d7c74017bb3e098e086ad4be0580d7056"
                );
        }

        [Test]
        public void TestString_A2Za2z09()
        {
            HashStringTest(
                "test #06",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "def6653091e3005b43a61681014a066cd189009d00856ee7"
                );
        }

        [Test]
        public void TestString_PiFraq()
        {
            HashStringTest(
                "test #07",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                "95bc146c17e355de03842c22d9fe3821fe7aaa9834f09c63"
                );
        }
    }
}
