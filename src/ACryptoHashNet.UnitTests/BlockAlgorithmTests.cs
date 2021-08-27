using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

namespace Home.Andir.Cryptography.UnitTests
{
    [TestFixture]
    [Category("BlockAlgorithmTests")]
    public class BlockAlgorithmTests
    {
        [Test]
        public static void BlockAlgorithmTest()
        {
            byte[] b1 = Encoding.UTF8.GetBytes("hello");
            byte[] b2 = Encoding.UTF8.GetBytes(" world");

            HashAlgorithm sha1Managed = new SHA1Managed();
            sha1Managed.TransformBlock(b1, 0, b1.Length, null, 0);
            var expected = 
                sha1Managed.TransformFinalBlock(b2, 0, b2.Length);

            HashAlgorithm sha1 = new SHA1();
            sha1.TransformBlock(b1, 0, b1.Length, null, 0);
            byte[] actual = 
                sha1.TransformFinalBlock(b2, 0, b2.Length);

            if (expected.Length != actual.Length)
            {
                Assert.Fail("Final block has wrong lengh");
            }

            for (int ii = 0; ii < expected.Length; ii++)
            {
                Assert.AreEqual(expected[ii], actual[ii], string.Format("Final block differ at {0} position", ii));
            }
        }
    }
}
