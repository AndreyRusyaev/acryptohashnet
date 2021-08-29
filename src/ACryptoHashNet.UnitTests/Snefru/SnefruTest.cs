using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    [Category("SnefruTests")]
    public class SnefruTest : BaseHashTest
    {
        public SnefruTest() :
            base("snefru", new Snefru())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "\n",
                "d9fcb3171c097fbba8c8f12aa0906bad"
                );
        }

        [Test]
        public void Test_1()
        {
            HashStringTest(
                "test #01",
                "1\n",
                "44ec420ce99c1f62feb66c53c24ae453"
                );
        }

        [Test]
        public void Test_12()
        {
            HashStringTest(
                "test #01",
                "12\n",
                "7182051aa852ef6fba4b6c9c9b79b317"
                );
        }

        [Test]
        public void Test_123()
        {
            HashStringTest(
                "test #01",
                "123\n",
                "bc3a50af82bf56d6a64732bc7b050a93"
                );
        }

        [Test]
        public void Test_1234()
        {
            HashStringTest(
                "test #01",
                "1234\n",
                "c5b8a04985a8eadfb4331a8988752b77"
                );
        }

        [Test]
        public void Test_12345()
        {
            HashStringTest(
                "test #01",
                "12345\n",
                "d559a2b62f6f44111324f85208723707"
                );
        }

        [Test]
        public void Test_123456()
        {
            HashStringTest(
                "test #01",
                "123456\n",
                "6cfb5e8f1da02bd167b01e4816686c30"
                );
        }

        [Test]
        public void Test_1234567()
        {
            HashStringTest(
                "test #01",
                "1234567\n",
                "29aa48325f275a8a7a01ba1543c54ba5"
                );
        }

        [Test]
        public void Test_12345678()
        {
            HashStringTest(
                "test #01",
                "12345678\n",
                "be862a6b68b7df887ebe00319cbc4a47"
                );
        }

        [Test]
        public void Test_123456789()
        {
            HashStringTest(
                "test #01",
                "123456789\n",
                "6103721ccd8ad565d68e90b0f8906163"
                );
        }

        [Test]
        public void Test_a()
        {
            HashStringTest(
                "test #01",
                "a",
                "bf5ce540ae51bc50399f96746c5a15bd"
                );
        }

        [Test]
        public void Test_abc()
        {
            HashStringTest(
                "test #01",
                "abc",
                "553d0648928299a0f22a275a02c83b10"
                );
        }

        [Test]
        public void Test_message_digest()
        {
            HashStringTest(
                "test #01",
                "message digest",
                "96d6f2f4112c4baf29f653f1594e2d5d"
                );
        }

        [Test]
        public void Test_A_Z_a_z_0_9()
        {
            HashStringTest(
                "test #01",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "0efd7f93a549f023b79781090458923e"
                );
        }

        [Test]
        public void Test_a_z()
        {
            HashStringTest(
                "test #01",
                "abcdefghijklmnopqrstuvwxyz",
                "7840148a66b91c219c36f127a0929606"
                );
        }

        [Test]
        public void Test_1_90_7()
        {
            HashStringTest(
                "test #01",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "d9204ed80bb8430c0b9c244fe485814a"
                );
        }
    }
}
