using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("SHATests")]
    public class SHA256Test : BaseHashTest
    {
        public SHA256Test() :
            base("sha256", new SHA256())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #02",
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                );
        }

        [Test]
        public void TestString_a_q()
        {
            HashStringTest(
                "test #03",
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
                );
        }

        [Test]
        public void TestString_a_u()
        {
            HashStringTest(
                "test #04",
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
                );
        }

        [Test]
        public void TestString_Linkoln()
        {
            HashStringTest(
                "test #05",
                "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.  Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battlefield of that war.  We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.  It is altogether fitting and proper that we should do this.  But, in a larger sense, we can not dedicate--we can not consecrate--we can not hallow--this ground.  The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.  The world will little note, nor long remember what we say here, but it can never forget what they did here.  It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.  It is rather for us to be here dedicated to the great task remaining before us--that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion--that we here highly resolve that these dead shall not have died in vain--that this nation, under God, shall have a new birth of freedom--and that government of the people, by the people, for the people, shall not perish from the earth.  -- President Abraham Lincoln, November 19, 1863",
                "4d25fccf8752ce470a58cd21d90939b7eb25f3fa418dd2da4c38288ea561e600"
                );
        }

        [Test]
        public void TestString_64byte()
        {
            HashStringTest(
                "test #06",
                "This is exactly 64 bytes long, not counting the terminating byte",
                "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8"
                );
        }

        [Test]
        public void TestString_63byte()
        {
            HashStringTest(
                "test #07",
                "For this sample, this 63-byte string will be used as input data",
                "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342"
                );
        }

        [Test]
        public void TestString_128byte()
        {
            HashStringTest(
                "test #08",
                "And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes",
                "0ab803344830f92089494fb635ad00d76164ad6e57012b237722df0d7ad26896"
                );
        }

        [Test]
        public void TestString_127byte()
        {
            HashStringTest(
                "test #09",
                "By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.",
                "e4326d0459653d7d3514674d713e74dc3df11ed4d30b4013fd327fdb9e394c26"
                );
        }
    }
}
