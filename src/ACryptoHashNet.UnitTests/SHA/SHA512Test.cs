using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("SHATests")]
    public class SHA512Test : BaseHashTest
    {
        public SHA512Test() :
            base("sha512", new SHA512())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #02",
                "abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                );
        }

        [Test]
        public void TestString_a_q()
        {
            HashStringTest(
                "test #03",
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
                + "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
                );
        }

        [Test]
        public void TestString_a_u()
        {
            HashStringTest(
                "test #04",
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
                );
        }

        [Test]
        public void TestString_Linkoln()
        {
            HashStringTest(
                "test #05",
                "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.  Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battlefield of that war.  We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.  It is altogether fitting and proper that we should do this.  But, in a larger sense, we can not dedicate--we can not consecrate--we can not hallow--this ground.  The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.  The world will little note, nor long remember what we say here, but it can never forget what they did here.  It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.  It is rather for us to be here dedicated to the great task remaining before us--that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion--that we here highly resolve that these dead shall not have died in vain--that this nation, under God, shall have a new birth of freedom--and that government of the people, by the people, for the people, shall not perish from the earth.  -- President Abraham Lincoln, November 19, 1863",
                "23450737795d2f6a13aa61adcca0df5eef6df8d8db2b42cd2ca8f783734217a7"
                + "3e9cabc3c9b8a8602f8aeaeb34562b6b1286846060f9809b90286b3555751f09"
                );
        }

        [Test]
        public void TestString_64byte()
        {
            HashStringTest(
                "test #06",
                "This is exactly 64 bytes long, not counting the terminating byte",
                "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a38"
                + "7d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030"
                );
        }

        [Test]
        public void TestString_63byte()
        {
            HashStringTest(
                "test #07",
                "For this sample, this 63-byte string will be used as input data",
                "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e"
                + "6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766"
                );
        }

        [Test]
        public void TestString_128byte()
        {
            HashStringTest(
                "test #08",
                "And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes",
                "97fb4ec472f3cb698b9c3c12a12768483e5b62bcdad934280750b4fa4701e5e0"
                + "550a80bb0828342c19631ba55a55e1cee5de2fda91fc5d40e7bee1d4e6d415b3"
                );
        }

        [Test]
        public void TestString_127byte()
        {
            HashStringTest(
                "test #09",
                "By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.",
                "d399507bbf5f2d0da51db1ff1fc51c1c9ff1de0937e00d01693b240e84fcc340"
                + "0601429f45c297acc6e8fcf1e4e4abe9ff21a54a0d3d88888f298971bd206cd5"
                );
        }
    }
}
