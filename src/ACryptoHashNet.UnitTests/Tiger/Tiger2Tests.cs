using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class Tiger2Tests : BaseHashTest
    {
        public Tiger2Tests() :
            base("Tiger2", new Tiger2())
        {
        }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "4441BE75F6018773C206C22745374B924AA8313FEF919F41"
                );
        }

        [Test]
        public void TestString_a()
        {
            HashStringTest(
                "test #02",
                "a",
                "67E6AE8E9E968999F70A23E72AEAA9251CBC7C78A7916636"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #02",
                "abc",
                "F68D7BC5AF4B43A06E048D7829560D4A9415658BB0B1F3BF"
                );
        }

        [Test]
        public void TestString_MessageDigest()
        {
            HashStringTest(
                "test #02",
                "message digest",
                "E29419A1B5FA259DE8005E7DE75078EA81A542EF2552462D"
                );
        }

        [Test]
        public void TestString_a_z()
        {
            HashStringTest(
                "test #02",
                "abcdefghijklmnopqrstuvwxyz",
                "F5B6B6A78C405C8547E91CD8624CB8BE83FC804A474488FD"
                );
        }

        [Test]
        public void TestString_A_Z_a_z_0_9()
        {
            HashStringTest(
                "test #05",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "EA9AB6228CEE7B51B77544FCA6066C8CBB5BBAE6319505CD"
                );
        }
    }
}
