using NUnit.Framework;

namespace Home.Andir.Cryptography.NUnitTests
{
    [TestFixture]
    [Category("SHATests")]
    public class SHA384Test : BaseHashTest
    {
        public SHA384Test() :
            base("sha384", new SHA384())
        { }

        [Test]
        public void TestEmptyString()
        {
            HashStringTest(
                "test #01",
                "",
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
                );
        }

        [Test]
        public void TestString_abc()
        {
            HashStringTest(
                "test #02",
                "abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
                );
        }

        [Test]
        public void TestString_a_q()
        {
            HashStringTest(
                "test #03",
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
                );
        }

        [Test]
        public void TestString_a_u()
        {
            HashStringTest(
                "test #04",
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
                );
        }

        [Test]
        public void TestString_Linkoln()
        {
            HashStringTest(
                "test #05",
                "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.  Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battlefield of that war.  We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.  It is altogether fitting and proper that we should do this.  But, in a larger sense, we can not dedicate--we can not consecrate--we can not hallow--this ground.  The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.  The world will little note, nor long remember what we say here, but it can never forget what they did here.  It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.  It is rather for us to be here dedicated to the great task remaining before us--that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion--that we here highly resolve that these dead shall not have died in vain--that this nation, under God, shall have a new birth of freedom--and that government of the people, by the people, for the people, shall not perish from the earth.  -- President Abraham Lincoln, November 19, 1863",
                "69cc75b95280bdd9e154e743903e37b1205aa382e92e051b1f48a6db9d0203f8a17c1762d46887037275606932d3381e"
                );
        }

        [Test]
        public void TestString_64byte()
        {
            HashStringTest(
                "test #06",
                "This is exactly 64 bytes long, not counting the terminating byte",
                "e28e35e25a1874908bf0958bb088b69f3d742a753c86993e9f4b1c4c21988f958bd1fe0315b195aca7b061213ac2a9bd"
                );
        }

        [Test]
        public void TestString_63byte()
        {
            HashStringTest(
                "test #07",
                "For this sample, this 63-byte string will be used as input data",
                "37b49ef3d08de53e9bd018b0630067bd43d09c427d06b05812f48531bce7d2a698ee2d1ed1ffed46fd4c3b9f38a8a557"
                );
        }

        [Test]
        public void TestString_128byte()
        {
            HashStringTest(
                "test #08",
                "And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes",
                "e3e3602f4d90c935321d788f722071a8809f4f09366f2825cd85da97ccd2955eb6b8245974402aa64789ed45293e94ba"
                );
        }

        [Test]
        public void TestString_127byte()
        {
            HashStringTest(
                "test #09",
                "By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.",
                "1ca650f38480fa9dfb5729636bec4a935ebc1cd4c0055ee50cad2aa627e066871044fd8e6fdb80edf10b85df15ba7aab"
                );
        }
    }
}
