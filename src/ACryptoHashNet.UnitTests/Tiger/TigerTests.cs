using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("TigerTests")]
    public class TigerTests : BaseHashTest
    {
        public TigerTests() :
            base("tiger", new Tiger())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #02",
                "abc",
                "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"
                );
        }

        [Test]
        public void TestString_Tiger()
        {
            HashStringTest(
                "test #03",
                "Tiger",
                "dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937"
                );
        }

        [Test]
        public void TestString_A_Za_z0_9()
        {
            HashStringTest(
                "test #04",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
                "f71c8583902afb879edfe610f82c0d4786a3a534504486b5"
                );
        }

        [Test]
        public void TestString_A_Z_a_z_0_9()
        {
            HashStringTest(
                "test #05",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789",
                "48ceeb6308b87d46e95d656112cdf18d97915f9765658957"
                );
        }

        [Test]
        public void TestString_Frase1()
        {
            HashStringTest(
                "test #06",
                "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham",
                "8a866829040a410c729ad23f5ada711603b3cdd357e4c15e"
                );
        }

        [Test]
        public void TestString_Frase2()
        {
            HashStringTest(
                "test #07",
                "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.",
                "ce55a6afd591f5ebac547ff84f89227f9331dab0b611c889"
                );
        }

        [Test]
        public void TestString_Frase3()
        {
            HashStringTest(
                "test #08",
                "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.",
                "631abdd103eb9a3d245b6dfd4d77b257fc7439501d1568dd"
                );
        }

        [Test]
        public void TestString_A_Za_z0_9_2()
        {
            HashStringTest(
                "test #09",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
                "c54034e5b43eb8005848a7e0ae6aac76e4ff590ae715fd25"
                );
        }

        [Test]
        public void TestString_64Kb()
        {
            byte[] testAr = new byte[65536];

            for (int ii = 0; ii < testAr.Length; ii++)
            {
                testAr[ii] = (byte)(ii & 0xff);
            }

            Assert.AreEqual(
                "fdf4f5b35139f48e710e421be5af411de1a8aac333f26204",
                StringUtils.ByteArrayToHexString(Algorithm.ComputeHash(testAr)),
                "test #10: tiger hash of 64kb string is wrong!");
        }
    }
}
