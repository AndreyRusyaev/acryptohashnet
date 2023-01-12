using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class LittleEndianTests
    {
        [Test]
        public void CopyBytesToUintsTest()
        {
            byte[] input = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12 };

            uint[] output = new uint[2];

            LittleEndian.Copy(input, output);

            CollectionAssert.AreEqual(
                new uint[] { 0x78563412, 0x12345678 },
                output);
        }

        [Test]
        public void CopyUintsToBytesTest()
        {
            uint[] input = new uint[] { 0x12345678, 0x78563412 };

            byte[] output = new byte[8];

            LittleEndian.Copy(input, output);

            CollectionAssert.AreEqual(
                new byte[] { 0x78, 0x56, 0x34, 0x12, 0x12, 0x34, 0x56, 0x78 },
                output);
        }

        [Test]
        public void CopyBytesToUlongsTest()
        {
            byte[] input = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF1, 0x1F, 0xED, 0xCB, 0xA9, 0x78, 0x56, 0x34, 0x12 };

            ulong[] output = new ulong[2];

            LittleEndian.Copy(input, output);

            CollectionAssert.AreEqual(
                new ulong[] { 0xF1DEBC9A78563412, 0x12345678A9CBED1F },
                output);
        }

        [Test]
        public void CopyUlongsToBytesTest()
        {
            ulong[] input = new ulong[] { 0x123456789ABCDEF1, 0x1FEDCBA978563412 };

            byte[] output = new byte[16];

            LittleEndian.Copy(input, output);

            CollectionAssert.AreEqual(
                new byte[] { 0xF1, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x12, 0x34, 0x56, 0x78, 0xA9, 0xCB, 0xED, 0x1F },
                output);
        }
    }
}
