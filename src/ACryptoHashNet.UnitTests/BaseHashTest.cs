using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

namespace acryptohashnet.UnitTests
{
    public class BaseHashTest
    {
        public BaseHashTest(string hashName, HashAlgorithm algorithm)
        {
            this.AlgorithmName = hashName;
            this.Algorithm = algorithm;
        }

        public string AlgorithmName { get; private set; }
        public HashAlgorithm Algorithm { get; private set; }

        protected string HashString(string input)
        {
            return HashString(input, Encoding.UTF8);
        }

        protected string HashString(string input, Encoding encoding)
        {
            var result = Algorithm.ComputeHash(
                encoding.GetBytes(input));

            return Utils.ByteArrayToHexString(result);
        }

        protected void HashStringTest(string testInfo,
            string source, string expected)
        {
            Assert.AreEqual(
                expected,
                HashString(source),
                string.Format("{1}: {0} hash of string = '{2}' is wrong!", 
                    this.AlgorithmName, testInfo, source)
                );
        }
    }
}
