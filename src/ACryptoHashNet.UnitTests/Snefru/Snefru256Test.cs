using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("SnefruTests")]
    public class Snefru256Test : BaseHashTest
    {
        public Snefru256Test() :
            base("snefru", new Snefru256())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "\n",
                "2e02687f0d45d5b9b50cb68c3f33e6843d618a1aca2d06893d3eb4e3026b5732"
                );
        }

        [Test]
        public void Test_1()
        {
            HashStringTest(
                "test #01",
                "1\n",
                "bfea4a05a2a2ef15c736d114598a20b9d9bd4d66b661e6b05ecf6a7737bdc58c"
                );
        }

        [Test]
        public void Test_12()
        {
            HashStringTest(
                "test #01",
                "12\n",
                "ac677d69761ade3f189c7aef106d5fe7392d324e19cc76d5db4a2c05f2cc2cc5"
                );
        }

        [Test]
        public void Test_123()
        {
            HashStringTest(
                "test #01",
                "123\n",
                "061c76aa1db4a22c0e42945e26c48499b5400162e08c640be05d3c007c44793d"
                );
        }

        [Test]
        public void Test_1234()
        {
            HashStringTest(
                "test #01",
                "1234\n",
                "1e87fe1d9c927e9e24be85e3cc73359873541640a6261793ce5a974953113f5e"
                );
        }

        [Test]
        public void Test_12345()
        {
            HashStringTest(
                "test #01",
                "12345\n",
                "1b59927d85a9349a87796620fe2ff401a06a7ba48794498ebab978efc3a68912"
                );
        }

        [Test]
        public void Test_123456()
        {
            HashStringTest(
                "test #01",
                "123456\n",
                "28e9d9bc35032b68faeda88101ecb2524317e9da111b0e3e7094107212d9cf72"
                );
        }

        [Test]
        public void Test_1234567()
        {
            HashStringTest(
                "test #01",
                "1234567\n",
                "f7fff4ee74fd1b8d6b3267f84e47e007f029d13b8af7e37e34d13b469b8f248f"
                );
        }

        [Test]
        public void Test_12345678()
        {
            HashStringTest(
                "test #01",
                "12345678\n",
                "ee7d64b0102b2205e98926613b200185559d08be6ad787da717c968744e11af3"
                );
        }

        [Test]
        public void Test_123456789()
        {
            HashStringTest(
                "test #01",
                "123456789\n",
                "4ca72639e40e9ab9c0c3f523c4449b3911632d374c124d7702192ec2e4e0b7a3"
                );
        }

        [Test]
        public void Test_a()
        {
            HashStringTest(
                "test #01",
                "a",
                "45161589ac317be0ceba70db2573ddda6e668a31984b39bf65e4b664b584c63d"
                );
        }

        [Test]
        public void Test_abc()
        {
            HashStringTest(
                "test #01",
                "abc",
                "7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b"
                );
        }

        [Test]
        public void Test_message_digest()
        {
            HashStringTest(
                "test #01",
                "message digest",
                "c5d4ce38daa043bdd59ed15db577500c071b917c1a46cd7b4d30b44a44c86df8"
                );
        }

        [Test]
        public void Test_A_Z_a_z_0_9()
        {
            HashStringTest(
                "test #01",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "83aa9193b62ffd269faa43d31e6ac2678b340e2a85849470328be9773a9e5728"
                );
        }

        [Test]
        public void Test_a_z()
        {
            HashStringTest(
                "test #01",
                "abcdefghijklmnopqrstuvwxyz",
                "9304bb2f876d9c4f54546cf7ec59e0a006bead745f08c642f25a7c808e0bf86e"
                );
        }

        [Test]
        public void Test_1_90_7()
        {
            HashStringTest(
                "test #01",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "d5fce38a152a2d9b83ab44c29306ee45ab0aed0e38c957ec431dab6ed6bb71b8"
                );
        }
    }
}
