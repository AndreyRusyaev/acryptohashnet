using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class BigCounterTests
    {
        [Test]
        public void Test_Add0()
        {
            BigCounter testCounter = new BigCounter(4);

            testCounter.Add(100);

            Assert.AreEqual(100, testCounter.ToUInt32());
        }

        [Test]
        public void Test_Add1()
        {
            BigCounter testCounter = new BigCounter(4);

            testCounter.Add(100);
            testCounter.Add(200);

            Assert.AreEqual(300, testCounter.ToUInt32());
        }

        [Test]
        public void Test_Add3()
        {
            BigCounter testCounter = new BigCounter(4);

            testCounter.Add(0xffff);
            testCounter.Add(0x1);

            Assert.AreEqual(0x010000, testCounter.ToUInt32());
        }

        [Test]
        public void Test_Add4()
        {
            BigCounter testCounter = new BigCounter(8);

            testCounter.Add(0xffffffff);
            testCounter.Add(0x1);

            Assert.AreEqual(0x0100000000, testCounter.ToULong());

            testCounter.Add(0x1);

            Assert.AreEqual(0x0100000001, testCounter.ToULong());

            testCounter.Add(0x0100000001);

            Assert.AreEqual(0x0200000002, testCounter.ToULong());

            testCounter.Add(0xffffffff);

            Assert.AreEqual(0x300000001, testCounter.ToULong());
        }

        [Test]
        public void Test_Add5()
        {
            BigCounter testCounter = new BigCounter(8);

            testCounter.Add(0xffffffff);
            testCounter.Add(0x1);

            byte[] result = testCounter.GetBytes();

            Assert.AreEqual(0x00, result[0]);
            Assert.AreEqual(0x00, result[1]);
            Assert.AreEqual(0x00, result[2]);
            Assert.AreEqual(0x00, result[3]);
            Assert.AreEqual(0x01, result[4]);
        }

    }
}
